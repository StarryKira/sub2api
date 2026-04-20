# sub2api-clandes

[中文](./README.zh.md) | English

A fork of [sub2api](https://github.com/Wei-Shaw/sub2api) with [clandes](https://github.com/Shirasuki/OpenClandes) integration — routing Claude Code traffic through a Rust-based decision/proxy plane while sub2api remains the billing, account, and admin plane.

> **Scope.** This README only documents what is different from upstream sub2api. For the base gateway — multi-account pooling, API-key generation, subscription billing, payments, etc. — read the [upstream README](https://github.com/Wei-Shaw/sub2api/blob/main/README.md) first.

---

## What clandes integration adds

clandes is a Rust binary that terminates Anthropic's TLS/HTTP/2 locally with fingerprint-stable client behavior. This fork wires sub2api to clandes over Cap'n Proto RPC so that:

- **OAuth login proceeds through clandes.** The browser callback hits clandes (not Anthropic directly), which proxies the code exchange and hands refresh tokens back to sub2api — bypassing the IP/fingerprint friction Claude imposes on browser OAuth.
- **Request routing is split.** clandes proxies the raw HTTP, while sub2api owns the routing decision via a `Router` Cap'n Proto capability: sub2api picks the account, enforces quota/balance, and returns a `routed` or `rejected` result synchronously.
- **Sticky sessions by `x-claude-code-session-id`.** Every request from the same Claude Code process routes to the same upstream account, preserving the prompt cache for the entire CLI session.
- **Billing is usage-report-driven.** clandes calls `reportUsage` on every terminal state (success / upstream error / client cancel / network error) with token counts and HTTP status, so concurrency slots and billing are released promptly rather than waiting on a TTL.
- **Admin UI surfaces clandes status.** A new admin page shows integration state, connection state, server address, and — via `getVersion` RPC — the running clandes-server binary version.

## Architecture

```
  Claude Code ──▶ clandes (Rust proxy)   ◀──RPC──▶ sub2api (Go)
                    │                               │
                    │ TLS/HTTP2 to Anthropic        │ Router capability
                    │ (fingerprint-stable)          │ + UsageReport callback
                    ▼                               │
              Anthropic API ───────────────────────▶│
                                                    │
                                              PostgreSQL / Redis
```

- Control plane: sub2api (account selection, billing, admin dashboard)
- Data plane: clandes (TLS termination, header shaping, proxy upstream)
- Transport: Cap'n Proto RPC over TCP (`backend/internal/pkg/clandes/proto/*.capnp`)

## Quick start

### Run with Docker

```bash
docker pull ghcr.io/starrykira/sub2api:0.1.114-clandes.1
```

Plus a running clandes server on `127.0.0.1:8082` (see [clandes repo](https://github.com/Shirasuki/OpenClandes) for build/run).

### Configuration

Copy `deploy/config.example.yaml` and enable the `clandes` section:

```yaml
clandes:
  enabled: true
  addr: "127.0.0.1:8082"       # clandes RPC endpoint
  auth_token: ""               # must match clandes RPC_AUTH_TOKEN
  reconnect_interval: 5        # seconds
```

When enabled, sub2api on startup:

1. Dials clandes over Cap'n Proto RPC
2. Calls `ClandesService.getVersion` to record the peer version
3. Syncs all accounts flagged as `clandes_only` to clandes via `AccountService`
4. Registers its `Router` capability via `PolicyService.connect`
5. Reconnects on drop (flushing held concurrency slots from in-flight requests)

### Build from source

Same as upstream:

```bash
make build                                                     # backend + frontend
cd backend && make generate                                    # Ent + Wire
cd backend && go generate ./internal/pkg/clandes/proto         # capnp bindings
```

## Project layout (clandes-specific)

| Path | Purpose |
|------|---------|
| `backend/internal/pkg/clandes/proto/` | Cap'n Proto schemas (synced from upstream clandes) + generated Go bindings |
| `backend/internal/service/clandes_client.go` | RPC client, connect/reconnect loop, sub-capability management |
| `backend/internal/service/clandes_router.go` | `Router` server impl — `routeRequest` / `reportUsage` / `reportChunk` / `onAccountEvent` |
| `backend/internal/service/clandes_request_cache.go` | In-flight request cache (5-min TTL fallback for slot release) |
| `backend/internal/handler/admin/clandes_handler.go` | Admin REST endpoints (`/api/v1/admin/clandes/*`) |
| `frontend/src/views/admin/ClandesView.vue` | Admin UI — status, version, account sync, OAuth |

## Divergence from upstream

This fork tracks `Wei-Shaw/sub2api` main and layers clandes-only commits on top. Notable fixes on this branch not yet in upstream:

- Resolve subscription before billing check so quota users with zero balance aren't rejected
- Hold concurrency slot until `reportUsage` instead of releasing at `routeRequest` return
- Treat connection failure as "disconnected" (not "not-enabled") in admin status
- `common.capnp` / `proxy.capnp` / `clandes.capnp` synced with upstream clandes (ProbeTiming, probe timing, getVersion)

See git log for the full set.

## Docker images

Published to GitHub Container Registry:

```
ghcr.io/starrykira/sub2api:<version>-clandes[.<revision>]
```

| Tag | Content |
|-----|---------|
| `0.1.114-clandes` | Initial clandes build |
| `0.1.114-clandes.1` | + subscription-before-billing fix, proto sync, version display |

## License

Inherits the upstream [sub2api license](https://github.com/Wei-Shaw/sub2api/blob/main/LICENSE).

## Credits

- [Wei-Shaw/sub2api](https://github.com/Wei-Shaw/sub2api) — base gateway
- [clandes](https://github.com/Shirasuki/OpenClandes) — Rust proxy/decision plane