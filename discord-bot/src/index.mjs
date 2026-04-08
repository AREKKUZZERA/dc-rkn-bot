import 'dotenv/config';
import { Client, GatewayIntentBits, REST, Routes, SlashCommandBuilder } from 'discord.js';
import fs from 'node:fs/promises';
import path from 'node:path';

const env = process.env;
const DISCORD_TOKEN = env.DISCORD_TOKEN;
const DISCORD_CLIENT_ID = env.DISCORD_CLIENT_ID;
const DISCORD_GUILD_ID = env.DISCORD_GUILD_ID;
const DISCORD_NOTIFY_CHANNEL_ID = env.DISCORD_NOTIFY_CHANNEL_ID;
const CHEBURCHECK_API_BASE = (env.CHEBURCHECK_API_BASE || 'http://127.0.0.1:8000/api').replace(/\/$/, '');
const POLL_INTERVAL_MS = Number(env.POLL_INTERVAL_MS || '60000');
const BOT_STATE_FILE = env.BOT_STATE_FILE || './data/bot-state.json';
const BOT_SKIP_INITIAL_UPDATES = (env.BOT_SKIP_INITIAL_UPDATES || 'true').toLowerCase() !== 'false';

if (!DISCORD_TOKEN || !DISCORD_CLIENT_ID || !DISCORD_GUILD_ID || !DISCORD_NOTIFY_CHANNEL_ID) {
  console.error('Missing required environment variables. See discord-bot/.env.example');
  process.exit(1);
}

const commands = [
  new SlashCommandBuilder()
    .setName('rkn-list')
    .setDescription('Показать страницу списка блокировок')
    .addIntegerOption(option => option.setName('page').setDescription('Страница').setMinValue(1))
    .addStringOption(option => option.setName('kind').setDescription('Тип').addChoices(
      { name: 'Все', value: 'all' },
      { name: 'Домены', value: 'domain' },
      { name: 'Подсети', value: 'subnet' },
    )),
  new SlashCommandBuilder()
    .setName('rkn-search')
    .setDescription('Поиск по списку блокировок')
    .addStringOption(option => option.setName('query').setDescription('Строка поиска').setRequired(true))
    .addStringOption(option => option.setName('kind').setDescription('Тип').addChoices(
      { name: 'Все', value: 'all' },
      { name: 'Домены', value: 'domain' },
      { name: 'Подсети', value: 'subnet' },
    )),
  new SlashCommandBuilder()
    .setName('rkn-new')
    .setDescription('Новые блокировки с последнего обновления списка')
    .addIntegerOption(option => option.setName('limit').setDescription('Сколько записей показать').setMinValue(1).setMaxValue(100)),
  new SlashCommandBuilder()
    .setName('rkn-stats')
    .setDescription('Статистика по списку блокировок'),
].map(command => command.toJSON());

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

function escapeMarkdown(text) {
  return String(text).replace(/([\\_*~`>|])/g, '\\$1');
}

async function ensureStateDir() {
  await fs.mkdir(path.dirname(BOT_STATE_FILE), { recursive: true });
}

async function readState() {
  try {
    const raw = await fs.readFile(BOT_STATE_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return { lastProcessedRefresh: null };
  }
}

async function writeState(state) {
  await ensureStateDir();
  await fs.writeFile(BOT_STATE_FILE, JSON.stringify(state, null, 2));
}

async function api(pathname, params = {}) {
  const url = new URL(`${CHEBURCHECK_API_BASE}${pathname}`);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '' && value !== 'all') {
      url.searchParams.set(key, String(value));
    }
  }

  const res = await fetch(url);
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`API ${url} failed: ${res.status} ${body}`);
  }
  return res.json();
}

function formatEntries(items, numbered = false, offset = 0) {
  if (!items?.length) {
    return 'Ничего не найдено.';
  }

  return items.map((item, index) => {
    const prefix = numbered ? `${offset + index + 1}. ` : '• ';
    const kind = item.kind === 'domain' ? 'domain' : 'subnet';
    return `${prefix}\`${escapeMarkdown(item.value)}\` (${kind})`;
  }).join('\n');
}

async function registerCommands() {
  const rest = new REST({ version: '10' }).setToken(DISCORD_TOKEN);
  await rest.put(
    Routes.applicationGuildCommands(DISCORD_CLIENT_ID, DISCORD_GUILD_ID),
    { body: commands },
  );
  console.log('Slash commands registered');
}

async function sendUpdateMessages(payload) {
  const channel = await client.channels.fetch(DISCORD_NOTIFY_CHANNEL_ID);
  if (!channel?.isTextBased()) {
    throw new Error('Notification channel is not text-based or not accessible');
  }

  const header = `🚫 **Новые блокировки**\nОбновление: ${payload.last_refresh}\nНовых записей: **${payload.total_new}**`;
  const items = payload.items || [];

  if (!items.length) {
    await channel.send({ content: header });
    return;
  }

  const chunkSize = 20;
  for (let i = 0; i < items.length; i += chunkSize) {
    const chunk = items.slice(i, i + chunkSize);
    const content = i === 0
      ? `${header}\n${formatEntries(chunk)}`
      : formatEntries(chunk);
    await channel.send({ content });
  }
}

async function pollUpdates() {
  const payload = await api('/updates', { limit: 100 });
  if (!payload.last_refresh) {
    return;
  }

  const state = await readState();
  if (!state.lastProcessedRefresh && BOT_SKIP_INITIAL_UPDATES) {
    state.lastProcessedRefresh = payload.last_refresh;
    await writeState(state);
    console.log(`Initial refresh stored: ${payload.last_refresh}`);
    return;
  }

  if (state.lastProcessedRefresh === payload.last_refresh) {
    return;
  }

  if ((payload.total_new || 0) > 0) {
    await sendUpdateMessages(payload);
  }

  state.lastProcessedRefresh = payload.last_refresh;
  await writeState(state);
  console.log(`Processed refresh: ${payload.last_refresh}`);
}

client.once('ready', async () => {
  console.log(`Logged in as ${client.user.tag}`);
  await registerCommands();
  await pollUpdates().catch(error => console.error('Initial poll failed', error));
  setInterval(() => {
    pollUpdates().catch(error => console.error('Polling failed', error));
  }, POLL_INTERVAL_MS);
});

client.on('interactionCreate', async interaction => {
  if (!interaction.isChatInputCommand()) {
    return;
  }

  try {
    if (interaction.commandName === 'rkn-list') {
      const page = interaction.options.getInteger('page') || 1;
      const kind = interaction.options.getString('kind') || 'all';
      const payload = await api('/blocked', { page, limit: 20, kind });
      const title = `Список блокировок · страница ${payload.page}/${Math.max(payload.total_pages || 1, 1)}`;
      const stats = `Всего: **${payload.total}**, доменов: **${payload.total_domains}**, подсетей: **${payload.total_subnets}**`;
      const body = formatEntries(payload.items, true, (payload.page - 1) * payload.limit);
      await interaction.reply({ content: `${title}\n${stats}\n${body}` });
      return;
    }

    if (interaction.commandName === 'rkn-search') {
      const query = interaction.options.getString('query', true);
      const kind = interaction.options.getString('kind') || 'all';
      const payload = await api('/blocked', { page: 1, limit: 20, query, kind });
      const title = `Поиск по \`${escapeMarkdown(query)}\``;
      const body = formatEntries(payload.items, true, 0);
      await interaction.reply({ content: `${title}\nНайдено: **${payload.total}**\n${body}` });
      return;
    }

    if (interaction.commandName === 'rkn-new') {
      const limit = interaction.options.getInteger('limit') || 20;
      const payload = await api('/updates', { limit });
      const body = formatEntries(payload.items, true, 0);
      await interaction.reply({ content: `Последнее обновление: ${payload.last_refresh || 'нет данных'}\nНовых записей: **${payload.total_new || 0}**\n${body}` });
      return;
    }

    if (interaction.commandName === 'rkn-stats') {
      const payload = await api('/stats');
      await interaction.reply({
        content: [
          `Последнее обновление: ${payload.last_refresh || 'нет данных'}`,
          `Предыдущее обновление: ${payload.previous_refresh || 'нет данных'}`,
          `Всего записей: **${payload.total_entries}**`,
          `Домены: **${payload.total_domains}**`,
          `Подсети: **${payload.total_subnets}**`,
          `Новых за последнее обновление: **${payload.total_new}**`,
        ].join('\n')
      });
    }
  } catch (error) {
    console.error(error);
    const content = 'Ошибка при обращении к API Cheburcheck.';
    if (interaction.deferred || interaction.replied) {
      await interaction.followUp({ content, ephemeral: true });
    } else {
      await interaction.reply({ content, ephemeral: true });
    }
  }
});

client.login(DISCORD_TOKEN);
