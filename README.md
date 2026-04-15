# Waiteway

Gateways made simple.

- https://waiteway.waisuite.com/waipage
- https://waiteway.waisuite.com/wailey
- https://waiteway.waisuite.com/waiconv

## What it does

- reverse proxy by path prefix
- per-route API keys
- admin portal with login
- request logging persisted in SQLite
- health endpoint
- separate gateway and admin ports

## Ports

| port | purpose |
|---|---|
| 8080 | gateway — proxies requests to upstream services |
| 9090 | admin — login, routes, logs, settings |

The gateway port only proxies. The admin port only serves the portal. They are fully separate.

## Run locally

```bash
go run .
```

Creates `waiteway.db` on first run with an example route.

Default login:

- username: `admin`
- password: `change-me`

Open the admin portal at `http://localhost:9090`.

## Run with Docker

```bash
docker build -t waiteway .
docker run -p 8080:8080 -p 9090:9090 -v ./data:/data waiteway
```

## Run with Kubernetes

### Add the Helm repo

```bash
helm repo add waiteway https://wbattles.github.io/waiteway
```

### Install

```bash
helm install waiteway waiteway/waiteway \
  --set admin.password=your-password
```

### Use your own secret

```bash
kubectl create secret generic my-admin-creds \
  --from-literal=username=admin \
  --from-literal=password=your-password

helm install waiteway waiteway/waiteway \
  --set admin.existingSecret=my-admin-creds
```

### Helm values

| key | default | description |
|---|---|---|
| `image.repository` | `waiteway` | container image |
| `image.tag` | `latest` | image tag |
| `admin.username` | `admin` | initial admin username |
| `admin.password` | `""` | initial admin password |
| `admin.existingSecret` | `""` | use an existing k8s secret instead |
| `admin.usernameKey` | `username` | key in existing secret for username |
| `admin.passwordKey` | `password` | key in existing secret for password |
| `service.gateway.type` | `ClusterIP` | gateway service type |
| `service.gateway.port` | `8080` | gateway service port |
| `service.admin.type` | `ClusterIP` | admin service type |
| `service.admin.port` | `9090` | admin service port |
| `ingress.gateway.enabled` | `false` | enable gateway ingress |
| `ingress.gateway.className` | `""` | ingress class (e.g. nginx, traefik) |
| `ingress.gateway.hosts` | `api.example.com` | gateway hostname |
| `ingress.admin.enabled` | `false` | enable admin ingress |
| `ingress.admin.className` | `""` | ingress class |
| `ingress.admin.hosts` | `admin.example.com` | admin hostname |
| `persistence.enabled` | `true` | enable PVC for SQLite |
| `persistence.size` | `1Gi` | PVC size |
| `resources.requests.cpu` | `50m` | CPU request |
| `resources.requests.memory` | `64Mi` | memory request |

## Environment variables

Waiteway reads these on **first run only**. Once the database has settings, env vars are ignored. Admin portal changes stick after that. To re-seed from env vars, delete the database file.

| variable | description |
|---|---|
| `WAITEWAY_ADMIN_USERNAME` | admin username |
| `WAITEWAY_ADMIN_PASSWORD` | admin password |
| `WAITEWAY_LISTEN` | gateway listen address (default `:8080`) |
| `WAITEWAY_ADMIN_LISTEN` | admin listen address (default `:9090`) |

Ports are set by environment variables or defaults only. They cannot be changed from the admin portal.

## Admin portal

Three tabs:

- **gateway** — add, edit, delete routes. set per-route API keys.
- **logging** — view request logs, stats, top routes.
- **settings** — change password, username, log limit.

## Adding a route

1. Open the admin portal
2. Go to the gateway tab
3. Click add route
4. Set the name, path prefix, target, and auth
5. Save

Requests matching the path prefix get proxied to the target.

## Architecture

```
internet → tunnel/ingress → waiteway :8080 → upstream services
                            waiteway :9090 → admin portal (internal)
```

In a cluster, only expose the gateway service. Keep the admin service internal.
