# sub2api-clandes

中文 | [English](./README.md)

[sub2api](https://github.com/Wei-Shaw/sub2api) 的一个 fork，集成了 [clandes](https://github.com/Shirasuki/OpenClandes) —— 让 Rust 写的决策/代理层去处理 Claude Code 流量，sub2api 仍然负责计费、账号和后台管理。

> **本 README 只说明与上游 sub2api 的差异。** 基础网关能力（多账号池、API Key 下发、订阅计费、支付等）请先看[上游 README](https://github.com/Wei-Shaw/sub2api/blob/main/README.md)。

---

## clandes 集成带来了什么

clandes 是一个本地代理 Anthropic TLS/HTTP2 的 Rust 二进制，提供指纹稳定的客户端实现。这个 fork 通过 Cap'n Proto RPC 把 sub2api 和 clandes 对接：

- **OAuth 登录走 clandes。** 浏览器回调打到 clandes（而不是 Anthropic），由 clandes 代理 code 交换、把 refresh token 返回给 sub2api —— 绕过 Claude 对浏览器 OAuth 的 IP / 指纹限制。
- **请求路由分层。** clandes 代理原始 HTTP，sub2api 通过 `Router` capability 做路由决策：选账号、检查配额/余额，同步返回 `routed` 或 `rejected`。
- **基于 `x-claude-code-session-id` 的粘性会话。** 同一个 Claude Code 进程的请求都路由到同一账号，保留整个 CLI 会话的 prompt cache。
- **用量回调驱动的计费。** clandes 在所有终止状态（成功 / 上游错误 / 客户端取消 / 网络错误）都会调用 `reportUsage`，带 token 数和 HTTP 状态码，并发槽和计费都能及时释放，不用等 TTL 超时。
- **后台面板显示 clandes 状态。** 新增一个后台页展示集成状态、连接状态、服务器地址，以及通过 `getVersion` RPC 读取的 clandes-server 版本号。

## 架构

```
  Claude Code ──▶ clandes (Rust proxy)   ◀──RPC──▶ sub2api (Go)
                    │                               │
                    │ TLS/HTTP2 到 Anthropic        │ Router capability
                    │ (指纹稳定)                    │ + UsageReport 回调
                    ▼                               │
              Anthropic API ───────────────────────▶│
                                                    │
                                              PostgreSQL / Redis
```

- 控制面：sub2api（账号选择、计费、后台管理）
- 数据面：clandes（TLS 终止、header 塑形、上游代理）
- 传输：TCP 上的 Cap'n Proto RPC（`backend/internal/pkg/clandes/proto/*.capnp`）

## 快速开始

### Docker 运行

```bash
docker pull ghcr.io/starrykira/sub2api:0.1.114-clandes.1
```

同时需要一个跑在 `127.0.0.1:8082` 的 clandes 服务（构建和运行方式见 [clandes 仓库](https://github.com/Shirasuki/OpenClandes)）。

### 配置

复制 `deploy/config.example.yaml`，启用 `clandes` 段：

```yaml
clandes:
  enabled: true
  addr: "127.0.0.1:8082"       # clandes RPC 地址
  auth_token: ""               # 需与 clandes 的 RPC_AUTH_TOKEN 一致
  reconnect_interval: 5        # 重连间隔（秒）
```

启用后 sub2api 启动时会：

1. 通过 Cap'n Proto RPC 连接 clandes
2. 调 `ClandesService.getVersion` 记录对端版本
3. 把所有 `clandes_only` 账号同步到 clandes（走 `AccountService`）
4. 通过 `PolicyService.connect` 注册自己的 `Router` capability
5. 连接断开时自动重连，并清空所有在途请求占用的并发槽

### 从源码构建

与上游一致：

```bash
make build                                                     # 后端 + 前端
cd backend && make generate                                    # Ent + Wire
cd backend && go generate ./internal/pkg/clandes/proto         # capnp 绑定
```

## 目录结构（clandes 相关）

| 路径 | 用途 |
|------|------|
| `backend/internal/pkg/clandes/proto/` | Cap'n Proto schema（与上游 clandes 同步）+ 生成的 Go 绑定 |
| `backend/internal/service/clandes_client.go` | RPC 客户端，连接/重连循环，子 capability 管理 |
| `backend/internal/service/clandes_router.go` | `Router` 服务端实现 —— `routeRequest` / `reportUsage` / `reportChunk` / `onAccountEvent` |
| `backend/internal/service/clandes_request_cache.go` | 在途请求缓存（5 分钟 TTL，作为并发槽释放的兜底） |
| `backend/internal/handler/admin/clandes_handler.go` | 后台 REST 接口（`/api/v1/admin/clandes/*`） |
| `frontend/src/views/admin/ClandesView.vue` | 后台面板 —— 状态、版本号、账号同步、OAuth |

## 与上游的差异

这个 fork 跟踪 `Wei-Shaw/sub2api` main，在上面叠加了 clandes 相关提交。本分支上尚未进入上游的修复：

- 计费检查前先解析订阅，防止配额用户 0 余额被误拦截
- 并发槽持有到 `reportUsage` 才释放（原先在 `routeRequest` 返回时就释放了）
- 连接失败时显示"已断开"而非"未启用"
- 同步 `common.capnp` / `proxy.capnp` / `clandes.capnp`（新增 ProbeTiming、probe timing、getVersion）

完整列表见 git log。

## Docker 镜像

发布在 GitHub Container Registry：

```
ghcr.io/starrykira/sub2api:<version>-clandes[.<revision>]
```

| Tag | 内容 |
|-----|------|
| `0.1.114-clandes` | 初始 clandes 构建 |
| `0.1.114-clandes.1` | 增加订阅先于计费检查的修复、proto 同步、版本号展示 |

## 许可证

继承上游 [sub2api 的许可证](https://github.com/Wei-Shaw/sub2api/blob/main/LICENSE)。

## 致谢

- [Wei-Shaw/sub2api](https://github.com/Wei-Shaw/sub2api) —— 基础网关
- [clandes](https://github.com/Shirasuki/OpenClandes) —— Rust 代理/决策层
