#[macro_use]
extern crate rocket;
mod agency;
mod db;
mod whitelist;

use crate::db::{check_whitelist, save_query, WhitelistedEntry};
use chrono::{DateTime, Utc};
use env_logger::Env;
use log::{error, info, warn, LevelFilter};
use querying::target::Target;
use querying::{Check, CheckError, CheckVerdict, Checker};
use rocket::fairing::AdHoc;
use rocket::form::FromForm;
use rocket::fs::FileServer;
use rocket::http::Status;
use rocket::response::content::RawJavaScript;
use rocket::serde::json::Json;
use rocket::tokio::sync::RwLock;
use rocket::tokio::time;
use rocket::{fairing, tokio, Build, Request, Rocket, State};
use rocket_cache_response::CacheResponse;
use rocket_client_addr::ClientRealAddr;
use rocket_dyn_templates::{context, Metadata, Template};
use serde::Serialize;
use sqlx::postgres::PgPool;
use sqlx::types::Uuid;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Serialize)]
struct GlobalContext {
    version: &'static str,
}

impl GlobalContext {
    fn new() -> Self {
        GlobalContext {
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum BlockedEntryKind {
    Domain,
    Subnet,
}

#[derive(Debug, Clone, Serialize)]
struct BlockedEntry {
    id: String,
    kind: BlockedEntryKind,
    value: String,
    source: &'static str,
}

#[derive(Debug, Default)]
struct BlocklistState {
    initialized: bool,
    current_ids: HashSet<String>,
    current_entries: Vec<BlockedEntry>,
    new_entries: Vec<BlockedEntry>,
    last_refresh: Option<DateTime<Utc>>,
    previous_refresh: Option<DateTime<Utc>>,
    total_domains: usize,
    total_subnets: usize,
}

#[derive(Debug, Default, FromForm)]
struct BlockedQuery {
    page: Option<usize>,
    limit: Option<usize>,
    kind: Option<String>,
    query: Option<String>,
}

#[derive(Debug, Default, FromForm)]
struct UpdatesQuery {
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct BlockedListResponse {
    page: usize,
    limit: usize,
    total: usize,
    total_pages: usize,
    total_domains: usize,
    total_subnets: usize,
    last_refresh: Option<DateTime<Utc>>,
    items: Vec<BlockedEntry>,
}

#[derive(Debug, Serialize)]
struct BlockedUpdatesResponse {
    last_refresh: Option<DateTime<Utc>>,
    previous_refresh: Option<DateTime<Utc>>,
    total_new: usize,
    items: Vec<BlockedEntry>,
}

#[derive(Debug, Serialize)]
struct BlockedStatsResponse {
    last_refresh: Option<DateTime<Utc>>,
    previous_refresh: Option<DateTime<Utc>>,
    total_entries: usize,
    total_domains: usize,
    total_subnets: usize,
    total_new: usize,
}

async fn collect_blocked_entries(checker: &Checker) -> Vec<BlockedEntry> {
    let mut entries: Vec<BlockedEntry> = checker
        .blocked_domains()
        .await
        .into_iter()
        .map(|value| BlockedEntry {
            id: format!("domain:{value}"),
            kind: BlockedEntryKind::Domain,
            value,
            source: "ru_blacklist",
        })
        .collect();

    entries.extend(
        checker
            .blocked_subnets()
            .await
            .into_iter()
            .map(|value| {
                let value = value.to_string();
                BlockedEntry {
                    id: format!("subnet:{value}"),
                    kind: BlockedEntryKind::Subnet,
                    value,
                    source: "ru_blacklist",
                }
            }),
    );

    entries.sort_by(|a, b| match (&a.kind, &b.kind) {
        (BlockedEntryKind::Domain, BlockedEntryKind::Subnet) => std::cmp::Ordering::Less,
        (BlockedEntryKind::Subnet, BlockedEntryKind::Domain) => std::cmp::Ordering::Greater,
        _ => a.value.cmp(&b.value),
    });

    entries
}

async fn refresh_blocklist_state(
    state: &Arc<RwLock<BlocklistState>>,
    checker: &Checker,
) {
    let entries = collect_blocked_entries(checker).await;
    let current_ids: HashSet<String> = entries.iter().map(|entry| entry.id.clone()).collect();
    let current_refresh = checker.last_update();
    let total_domains = entries
        .iter()
        .filter(|entry| matches!(entry.kind, BlockedEntryKind::Domain))
        .count();
    let total_subnets = entries.len().saturating_sub(total_domains);

    let mut snapshot = state.write().await;
    let new_entries = if snapshot.initialized {
        entries
            .iter()
            .filter(|entry| !snapshot.current_ids.contains(&entry.id))
            .cloned()
            .collect()
    } else {
        Vec::new()
    };

    snapshot.initialized = true;
    snapshot.previous_refresh = snapshot.last_refresh.clone();
    snapshot.last_refresh = current_refresh;
    snapshot.current_ids = current_ids;
    snapshot.current_entries = entries;
    snapshot.new_entries = new_entries;
    snapshot.total_domains = total_domains;
    snapshot.total_subnets = total_subnets;
}

#[get("/")]
async fn index(checker: &State<Arc<RwLock<Checker>>>) -> Template {
    let checker_ref = checker.read().await;
    Template::render(
        "index",
        context! {
            global: GlobalContext::new(),
            domain_count: format_number(checker_ref.total_domains().await),
            v4_count: format_number(checker_ref.total_v4s().await),
            last_update: checker_ref.last_update(),
        },
    )
}

#[get("/kb/<page>")]
fn page(metadata: Metadata, page: &str) -> Option<Template> {
    let page = format!("pages/{}", page);
    if !metadata.contains_template(&page) {
        return None;
    }

    Some(Template::render(
        page,
        context! {
            global: GlobalContext::new(),
        },
    ))
}

#[get("/healthcheck")]
async fn healthcheck(checker: &State<Arc<RwLock<Checker>>>) -> (Status, String) {
    if checker.read().await.last_update().is_some() {
        (Status::Ok, "OK".to_string())
    } else {
        (Status::InternalServerError, "LOADING DATABASES".to_string())
    }
}

#[post("/feedback/<uuid>/<works>")]
async fn feedback(uuid: &str, works: bool, pool: &State<PgPool>, addr: &ClientRealAddr) -> Result<(), Status> {
    sqlx::query!(
        "INSERT INTO human_reports (id, source_ip, works) VALUES ($1, $2, $3)",
        Uuid::try_parse(uuid).map_err(|_| Status::BadRequest)?,
        addr.ip.to_string(),
        works
    ).execute(&**pool).await.map_err(|_| Status::InternalServerError)?;

    Ok(())
}

#[get("/check?<target>")]
async fn check(
    target: &str,
    checker: &State<Arc<RwLock<Checker>>>,
    addr: &ClientRealAddr,
    pool: &State<PgPool>,
) -> Result<Template, Status> {
    let target = Target::from(target.trim());
    let check = checker.read().await.check(target.clone()).await;

    let mut db = pool.acquire().await.map_err(|_| Status::InternalServerError)?;

    let id: Option<String> = if let Ok(check) = &check {
        match save_query(&mut *db, &target, check, addr, checker.read().await).await {
            Ok(id) => Some(id.to_string()),
            Err(e) => {
                warn!("Failed to save check: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    let whitelist: Option<WhitelistedEntry> = if let Target::Domain(domain) = &target {
        check_whitelist(domain, &mut *db)
            .await
            .map_err(|_| Status::InternalServerError)?
    } else {
        None
    };

    match check {
        Err(CheckError::NotFound) => Ok(Template::render(
            "empty",
            context! {
                global: GlobalContext::new(),
                target: target.to_query(),
                target_type: target.readable_type(),
            },
        )),
        Ok(Check {
            verdict: CheckVerdict::Clear,
            geo,
            ips,
            rkn_subnets,
            asn_info,
        }) => Ok(Template::render(
            "result",
            context! {
                id,
                global: GlobalContext::new(),
                found: false,
                target: target.to_query(),
                target_type: target.readable_type(),
                blocked_subnets: rkn_subnets.iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>(),
                whitelist,
                ips,
                geo,
                subnet_size: target.subnet_size(),
                asn_info,
            },
        )),
        Ok(Check {
            verdict:
                CheckVerdict::Blocked {
                    rkn_domain,
                    cdn_provider_subnets,
                },
            geo,
            rkn_subnets,
            ips,
            asn_info,
        }) => Ok(Template::render(
            "result",
            context! {
                id,
                global: GlobalContext::new(),
                found: true,
                domain: rkn_domain,
                providers: cdn_provider_subnets,
                blocked_subnets: rkn_subnets.iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>(),
                target: target.to_query(),
                target_type: target.readable_type(),
                whitelist,
                ips,
                geo,
                subnet_size: target.subnet_size(),
                asn_info,
            },
        )),
        Err(e) => {
            error!("check failed {:?}", e);
            Err(Status::InternalServerError)
        }
    }
}

#[get("/blocked?<params..>")]
async fn api_blocked(
    params: Option<BlockedQuery>,
    state: &State<Arc<RwLock<BlocklistState>>>,
) -> Json<BlockedListResponse> {
    let params = params.unwrap_or_default();
    let page = params.page.unwrap_or(1).max(1);
    let limit = params.limit.unwrap_or(50).clamp(1, 500);
    let normalized_query = params.query.as_ref().map(|query| query.trim().to_ascii_lowercase());
    let normalized_kind = params.kind.as_ref().map(|kind| kind.trim().to_ascii_lowercase());

    let snapshot = state.read().await;
    let filtered: Vec<BlockedEntry> = snapshot
        .current_entries
        .iter()
        .filter(|entry| match normalized_kind.as_deref() {
            Some("domain") => matches!(entry.kind, BlockedEntryKind::Domain),
            Some("subnet") | Some("ip") | Some("net") => matches!(entry.kind, BlockedEntryKind::Subnet),
            _ => true,
        })
        .filter(|entry| match normalized_query.as_deref() {
            Some(query) if !query.is_empty() => entry.value.to_ascii_lowercase().contains(query),
            _ => true,
        })
        .cloned()
        .collect();

    let total = filtered.len();
    let total_pages = if total == 0 { 0 } else { total.div_ceil(limit) };
    let start = (page - 1) * limit;
    let items = filtered.into_iter().skip(start).take(limit).collect();

    Json(BlockedListResponse {
        page,
        limit,
        total,
        total_pages,
        total_domains: snapshot.total_domains,
        total_subnets: snapshot.total_subnets,
        last_refresh: snapshot.last_refresh.clone(),
        items,
    })
}

#[get("/updates?<params..>")]
async fn api_updates(
    params: Option<UpdatesQuery>,
    state: &State<Arc<RwLock<BlocklistState>>>,
) -> Json<BlockedUpdatesResponse> {
    let params = params.unwrap_or_default();
    let limit = params.limit.unwrap_or(100).clamp(1, 500);
    let snapshot = state.read().await;

    Json(BlockedUpdatesResponse {
        last_refresh: snapshot.last_refresh.clone(),
        previous_refresh: snapshot.previous_refresh.clone(),
        total_new: snapshot.new_entries.len(),
        items: snapshot.new_entries.iter().take(limit).cloned().collect(),
    })
}

#[get("/stats")]
async fn api_stats(state: &State<Arc<RwLock<BlocklistState>>>) -> Json<BlockedStatsResponse> {
    let snapshot = state.read().await;

    Json(BlockedStatsResponse {
        last_refresh: snapshot.last_refresh.clone(),
        previous_refresh: snapshot.previous_refresh.clone(),
        total_entries: snapshot.current_entries.len(),
        total_domains: snapshot.total_domains,
        total_subnets: snapshot.total_subnets,
        total_new: snapshot.new_entries.len(),
    })
}

#[catch(default)]
fn default(status: Status, _req: &Request) -> Template {
    Template::render(
        "error",
        context! {
            global: GlobalContext::new(),
            status: status.code,
            reason: status.reason_lossy(),
        },
    )
}

#[derive(Debug, Serialize)]
struct JsonError {
    code: u16,
    info: String,
}

#[catch(default)]
fn api_error(status: Status, _: &Request) -> Json<JsonError> {
    Json(JsonError { code: status.code, info: status.reason_lossy().to_string() })
}

#[rocket::get("/lucide.js")]
fn lucide() -> CacheResponse<RawJavaScript<&'static [u8]>> {
    CacheResponse::Public {
        responder: RawJavaScript(include_bytes!(concat!(env!("OUT_DIR"), "/lucide.js"))),
        max_age: 604800,
        must_revalidate: false,
    }
}
#[rocket::get("/chart.js")]
fn chartjs() -> CacheResponse<RawJavaScript<&'static [u8]>> {
    CacheResponse::Public {
        responder: RawJavaScript(include_bytes!(concat!(env!("OUT_DIR"), "/chart.js"))),
        max_age: 604800,
        must_revalidate: false,
    }
}
#[rocket::get("/chartjs-plugin-datalabels.js")]
fn chartjs_datalabels() -> CacheResponse<RawJavaScript<&'static [u8]>> {
    CacheResponse::Public {
        responder: RawJavaScript(include_bytes!(concat!(env!("OUT_DIR"), "/chartjs-plugin-datalabels.js"))),
        max_age: 604800,
        must_revalidate: false,
    }
}

fn format_number(number: usize) -> String {
    number
        .to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap()
        .join(" ")
}

async fn run_migrations(rocket: Rocket<Build>) -> fairing::Result {
    match rocket.state::<PgPool>() {
        Some(db) => match sqlx::migrate!("./migrations").run(db).await {
            Ok(_) => Ok(rocket),
            Err(e) => {
                error!("Failed to run database migrations: {}", e);
                Err(rocket)
            }
        },
        None => Err(rocket),
    }
}

#[launch]
async fn rocket() -> _ {
    env_logger::Builder::from_env(Env::default().default_filter_or("warn"))
        .filter_module("website", LevelFilter::Info)
        .filter_module("querying", LevelFilter::Info)
        .init();

    let mut interval = time::interval(Duration::from_secs(
        std::env::var("DATABASE_INTERVAL_SECONDS")
            .unwrap_or("21600".to_string())
            .parse()
            .unwrap(),
    ));

    let checker = Arc::new(RwLock::new(Checker::new().await));
    let blocklist_state = Arc::new(RwLock::new(BlocklistState::default()));

    let checker_clone = checker.clone();
    let blocklist_state_clone = blocklist_state.clone();
    tokio::spawn(async move {
        info!("Refreshing DB every {:?}", interval.period());
        loop {
            interval.tick().await;
            info!("Updating all DBs");
            match Checker::download_all().await {
                Ok(bases) => {
                    info!("Downloaded, updating...");
                    checker_clone.read().await.update_all(bases).await;
                    {
                        let checker_guard = checker_clone.read().await;
                        refresh_blocklist_state(&blocklist_state_clone, &checker_guard).await;
                    }
                    info!("Updated databases");
                },
                Err(e) => log::error!("Failed to download all DBs: {}", e),
            }
        }
    });

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(std::env::var("DATABASE_MAX_CONNECTIONS")
            .unwrap_or("100".to_string())
            .parse()
            .unwrap())
        .min_connections(std::env::var("DATABASE_MIN_CONNECTIONS")
            .unwrap_or("10".to_string())
            .parse()
            .unwrap())
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(60))
        .connect(&dotenvy::var("DATABASE_URL").expect("DATABASE_URL must be set"))
        .await
        .expect("Failed to create database pool");

    rocket::build()
        .manage(checker)
        .manage(blocklist_state)
        .manage(pool)
        .attach(AdHoc::try_on_ignite("SQLx Migrations", run_migrations))
        .mount("/", routes![index, check, healthcheck, page, feedback])
        .mount("/api", routes![api_blocked, api_updates, api_stats])
        .mount("/vendor", routes![lucide, chartjs, chartjs_datalabels])
        .mount("/agency", routes![agency::upload_report])
        .mount("/whitelist", routes![whitelist::histogram, whitelist::export_csv])
        .register("/api", catchers![api_error])
        .register("/agency", catchers![api_error])
        .register("/", catchers![default])
        .mount("/", FileServer::from(PathBuf::from("static")))
        .attach(Template::fairing())
}
