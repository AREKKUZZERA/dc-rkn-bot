use crate::updater::{fetch_db, Updatable};
use async_trait::async_trait;
use ipnet::IpNet;
use ipnet_trie::IpnetTrie;
use log::info;
use serde::{de, Deserialize, Deserializer, Serializer};
use std::collections::{HashSet, VecDeque};
use std::io;
use std::io::{BufRead, Error, Read};
use std::net::IpAddr;
use std::str::FromStr;
use trie_rs::map::{Trie, TrieBuilder};

pub struct CdnList {
    trie: IpnetTrie<NetworkRecord>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Eq, PartialEq, Hash)]
pub struct NetworkRecord {
    pub provider: String,
    #[serde(deserialize_with = "deserialize_ip_net")]
    #[serde(serialize_with = "serialize_ip_net")]
    pub cidr: IpNet,
    pub region: Option<String>,
}

fn deserialize_ip_net<'de, D>(deserializer: D) -> Result<IpNet, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    FromStr::from_str(&s).map_err(de::Error::custom)
}

fn serialize_ip_net<S>(ip_net: &IpNet, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&ip_net.to_string())
}

impl CdnList {
    pub fn new() -> CdnList{
        CdnList { trie: IpnetTrie::new() }
    }

    pub fn load<R: Read>(list_reader: R) -> Result<Self, Error> {
        let mut list = Self::new();
        list.update(list_reader)?;
        Ok(list)
    }

    pub fn update<R: Read>(&mut self, list_reader: R) -> Result<(), Error>  {
        let mut trie = IpnetTrie::new();
        let mut rdr = csv::Reader::from_reader(list_reader);
        for result in rdr.deserialize() {
            let record: NetworkRecord = result?;
            trie.insert(record.cidr, record);
        }
        let (v4, v6) = trie.ip_count();
        info!("ip count: v4={}, v6={}", v4, v6);
        self.trie = trie;
        Ok(())
    }

    pub fn v4_count(&self) -> u32 {
        self.trie.ip_count().0
    }

    pub fn contains(&self, ip: &IpAddr) -> Option<NetworkRecord> {
        self.trie.longest_match(&IpNet::from(*ip)).map(|(_, net)| net.clone())
    }
}

#[async_trait]
impl Updatable for CdnList {
    type Base = VecDeque<u8>;

    async fn download() -> Result<Self::Base, Error> {
        Ok(VecDeque::from(fetch_db(Self::get_url(
            "CDN_SOURCE",
            "https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/all/all.csv"
        )).await?))
    }

    async fn install(&mut self, base: Self::Base) -> Result<(), Error> {
        self.update(base)
    }
}

pub struct RuBlacklist {
    ip_trie: IpnetTrie<()>,
    domain_trie: Trie<String, String>,
    domain_entries: Vec<String>,
    ip_entries: Vec<IpNet>,
    pub domain_count: usize,
}

impl RuBlacklist {
    pub fn new() -> RuBlacklist {
        RuBlacklist {
            ip_trie: Default::default(),
            domain_trie: TrieBuilder::new().build(),
            domain_entries: Vec::new(),
            ip_entries: Vec::new(),
            domain_count: 0
        }
    }

    pub fn load<R: BufRead>(ip_reader: R, domain_reader: R, custom_domains_reader: R) -> Result<Self, Error> {
        let mut list = Self::new();
        list.update(ip_reader, domain_reader, custom_domains_reader)?;
        Ok(list)
    }

    pub fn update<R: BufRead>(&mut self, ip_reader: R, domain_reader: R, custom_domains_reader: R) -> Result<(), Error>  {
        let mut ip_trie = IpnetTrie::new();
        let mut ip_entries = Vec::new();

        for net in ip_reader.lines() {
            let net = net?;
            let net = net.trim();
            if net.is_empty() {
                continue;
            }

            let net = IpNet::from_str(net)
                .map_err(|e| Error::new(io::ErrorKind::InvalidData, e))?;
            ip_trie.insert(net, ());
            ip_entries.push(net);
        }
        ip_entries.sort();
        ip_entries.dedup();

        let (v4, v6) = ip_trie.ip_count();
        info!("ip count: v4={}, v6={}", v4, v6);
        self.ip_trie = ip_trie;
        self.ip_entries = ip_entries;

        let mut domain_trie = TrieBuilder::new();
        let mut domain_entries = Vec::new();
        let mut seen_domains = HashSet::new();

        for domain in domain_reader.lines().chain(custom_domains_reader.lines()) {
            let domain = domain?;
            let domain = domain.trim().to_ascii_lowercase();
            if domain.is_empty() || !seen_domains.insert(domain.clone()) {
                continue;
            }

            domain_trie.insert(Self::domain_chunks(&domain), domain.clone());
            domain_entries.push(domain);
        }

        domain_entries.sort();
        let count = domain_entries.len();
        info!("domain count: {}", count);
        self.domain_count = count;
        self.domain_entries = domain_entries;
        self.domain_trie = domain_trie.build();
        Ok(())
    }

    pub fn v4_count(&self) -> u32 {
        self.ip_trie.ip_count().0
    }

    fn domain_chunks(domain: &str) -> Vec<String> {
        domain.split(".").collect::<Vec<_>>()
            .into_iter().map(|s| s.to_string())
            .rev().collect()
    }

    pub fn contains_ip(&self, ip: &IpAddr) -> Option<IpNet> {
        self.ip_trie.longest_match(&IpNet::from(*ip)).map(|(ip, _)| ip)
    }

    pub fn contains_domain(&self, domain: &str) -> Option<String> {
        self.domain_trie.common_prefix_search(Self::domain_chunks(domain)).next()
            .map(|(_, b): (Vec<_>, &String)| b).cloned()
    }

    pub fn all_domains(&self) -> &[String] {
        &self.domain_entries
    }

    pub fn all_subnets(&self) -> &[IpNet] {
        &self.ip_entries
    }
}

#[async_trait]
impl Updatable for RuBlacklist {
    type Base = (VecDeque<u8>, VecDeque<u8>, VecDeque<u8>);

    async fn download() -> Result<Self::Base, Error> {
        Ok((VecDeque::from(
            fetch_db(Self::get_url("RKN_NETS", "https://antifilter.network/download/ipsum.lst")).await?),
            VecDeque::from(
            fetch_db(Self::get_url("RKN_DOMAINS", "https://antifilter.download/list/domains.lst")).await?),
            VecDeque::from(include_bytes!("../dist-domains.txt").to_vec())
        ))
    }

    async fn install(&mut self, (nets, domains, custom_domains): Self::Base) -> Result<(), Error> {
        self.update(nets, domains, custom_domains)
    }
}
