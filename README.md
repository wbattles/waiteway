# Waiteway

[![Casino funds](https://img.shields.io/badge/Casino_funds-Ko--fi-ff5f5f?logo=ko-fi&logoColor=white)](https://ko-fi.com/wbattles)

Gateways made simple.

## Run

```bash
go run .
```

Creates `waiteway.db` on first run with an example route.

Default login: `admin` / `change-me`

Admin portal: `http://localhost:9090`

Gateway: `http://localhost:8080`

### Docker

```bash
docker build -t waiteway .
docker run -p 8080:8080 -p 9090:9090 -v ./data:/data waiteway
```

### Kubernetes

```bash
helm repo add waiteway https://wbattles.github.io/waiteway
helm install waiteway waiteway/waiteway --set admin.password=your-password
```

## How it works

Two ports. Fully separate.

| port | purpose |
|---|---|
| 8080 | gateway — proxies requests to upstreams |
| 9090 | admin portal |

## Admin portal

Four tabs: **gateway**, **policy**, **logging**, **settings**.

### Gateway tab

Add, edit, delete routes. Each route has:

- **name** — label for the route
- **path prefix** — incoming path to match
- **target** — upstream URL to proxy to
- **policy** — optional policy to attach
- **strip prefix** — remove the matched prefix before proxying

### Policy tab

Create reusable policies. Attach one policy to a route.

Click **add policy**, name it, then click **add feature** to pick what you need:

| feature | what it does |
|---|---|
| request timeout | stop slow upstream calls |
| retry | retry failed upstream calls |
| api key auth | require X-API-Key or Bearer token |
| basic auth | require username and password |
| rate limiting | limit requests per time window |
| method allow list | only allow specific HTTP methods |
| path rewrite | replace the matched path prefix |
| request headers | add or remove request headers |
| payload limit | reject request bodies over a size |
| request transform | find and replace in request body |
| caching | cache successful GET responses |
| response headers | add or remove response headers |
| response transform | find and replace in response body |
| response size limit | reject oversized upstream responses |
| cors | set allowed origins, methods, headers |
| ip allow list | only allow listed IPs or CIDRs |
| ip block list | deny listed IPs or CIDRs |
| circuit breaker | pause traffic to a failing upstream |

Each policy can have any combination of features.

### Logging tab

View recent requests, stats, and top routes.

Waiteway also writes request logs to stdout as JSON.

### Metrics

Admin port exposes Prometheus-style metrics at `/metrics`.

Current metrics:

- `waiteway_requests_total`
- `waiteway_errors_total`

The Helm chart adds Prometheus scrape annotations to the admin service by default.

If you use kube-prometheus-stack or another Prometheus Operator setup, enable the chart's `ServiceMonitor` too.

### Settings tab

Change admin username, password, and log limit.

## Environment variables

Read on first run only. After that, use the admin portal.

| variable | default | description |
|---|---|---|
| `WAITEWAY_ADMIN_USERNAME` | `admin` | admin username |
| `WAITEWAY_ADMIN_PASSWORD` | `change-me` | admin password |
| `WAITEWAY_LISTEN` | `:8080` | gateway listen address |
| `WAITEWAY_ADMIN_LISTEN` | `:9090` | admin listen address |
| `WAITEWAY_CA_CERT` | unset | path to a PEM file with extra root certs (see [Private certificates](#private-certificates)) |

## Private certificates

For upstreams using private CAs, self-signed certs, or networks that re-sign HTTPS traffic (Zscaler, Netskope, homelab, internal services). Point `WAITEWAY_CA_CERT` at a PEM file with the root cert(s).

Your cert is added to the system trust store. Public sites keep working.

### Local

```bash
WAITEWAY_CA_CERT=./root.pem go run .
```

### Docker

```bash
docker run \
  -p 8080:8080 -p 9090:9090 \
  -v ./data:/data \
  -v ./root.pem:/certs/root.pem:ro \
  -e WAITEWAY_CA_CERT=/certs/root.pem \
  waiteway
```

### Kubernetes

Put the cert in a ConfigMap, then set `extraVolumes`, `extraVolumeMounts`, and `extraEnv`:

```yaml
extraVolumes:
  - name: ca
    configMap:
      name: ca-bundle
extraVolumeMounts:
  - name: ca
    mountPath: /certs
    readOnly: true
extraEnv:
  - name: WAITEWAY_CA_CERT
    value: /certs/root.pem
```

### Multiple certs

PEM files can hold multiple certs. Concatenate them into one bundle:

```bash
cat root.pem intermediate.pem > bundle.pem
```

## Architecture

```
internet → waiteway :8080 → upstream services
            waiteway :9090 → admin portal (internal)
```

Keep the admin port internal. Only expose the gateway.

## License

This project is licensed under the MIT License – see the [LICENSE](LICENSE) file for details.
