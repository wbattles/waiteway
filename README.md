# Waiteway

Simple API gateway for Waisuite apps.

It routes requests, checks API keys, and gives you a small admin portal.

## What it does

- reverse proxy by path
- API key checks
- basic admin portal
- recent request log
- health endpoint

## Why

One clean entry point for Waisuite services.

Keep client apps simple.
Keep secrets off the client.

## Run

```bash
cp waiteway.example.json waiteway.json
go run .
```

Or pass a config path:

```bash
go run . ./waiteway.example.json
```

## Config

```json
{
  "listen": ":8080",
  "admin": {
    "username": "admin",
    "password": "change-me"
  },
  "api_keys": ["local-dev-key"],
  "log_limit": 100,
  "routes": [
    {
      "name": "wailey",
      "path_prefix": "/api/chat",
      "target": "http://localhost:3001",
      "require_api_key": true,
      "strip_prefix": false
    }
  ]
}
```

## Endpoints

- `/health` - status check
- `/admin` - admin portal
- route paths from your config

## Admin portal

The admin portal uses HTTP basic auth when `admin.username` and `admin.password` are set.

It shows:

- server info
- routes
- recent requests

## Notes

This is a small first version.

Good next steps:

- rate limits
- route editing in admin
- config reload
- upstream health checks
- TLS behind nginx or Caddy
