# Discord bot for Cheburcheck blocklist API

Бот использует новые endpoints сайта:

- `GET /api/blocked`
- `GET /api/updates`
- `GET /api/stats`

## Команды

- `/rkn-list [page] [kind]`
- `/rkn-search <query> [kind]`
- `/rkn-new [limit]`
- `/rkn-stats`

## Запуск

```bash
cd discord-bot
cp .env.example .env
npm install
npm start
```

## Что нужно в `.env`

- `DISCORD_TOKEN` — токен бота
- `DISCORD_CLIENT_ID` — application id
- `DISCORD_GUILD_ID` — guild id для регистрации slash-команд
- `DISCORD_NOTIFY_CHANNEL_ID` — канал, куда слать уведомления
- `CHEBURCHECK_API_BASE` — например `http://127.0.0.1:8000/api`
- `POLL_INTERVAL_MS` — как часто опрашивать `/api/updates`
- `BOT_STATE_FILE` — файл с сохраненным `last_refresh`
- `BOT_SKIP_INITIAL_UPDATES` — если `true`, бот при первом старте не шлет весь diff, а только запоминает текущий refresh
