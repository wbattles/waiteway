# Waiteway

Simple API gateway for Waisuite apps.

Routes requests, checks API keys, logs traffic, and gives you an admin portal.

## What it does

- reverse proxy by path
- per-route API keys
- admin portal with login
- request logging (persisted in SQLite)
- health endpoint

## Run

```bash
go run .
```

On first run, Waiteway creates `waiteway.db` with default settings and an example route.

Or pass a database path:

```bash
go run . ./my-gateway.db
```

## Default admin login

- username: `admin`
- password: `change-me`

Change these in the settings tab after first login.

## Endpoints

- `/health` — status check
- `/admin/login` — admin login
- `/admin` — admin portal
- everything else — proxied by route config

## Admin portal

Three tabs:

- **gateway** — manage routes (add, edit, delete)
- **logging** — view request logs and stats
- **settings** — change password, listen address, log limit

## Storage

All config, routes, logs, and sessions are stored in a single SQLite database.

Logs persist across restarts. Sessions persist across restarts.
