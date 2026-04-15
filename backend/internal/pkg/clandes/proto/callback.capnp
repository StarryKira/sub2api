@0xf5a6b7c8d9e0f1a2;

using Go = import "/go.capnp";
$Go.package("proto");
$Go.import("github.com/Wei-Shaw/sub2api/internal/pkg/clandes/proto");

struct UsageReport {
  accountId        @0 :Text;
  apiKey           @1 :Text;
  model            @2 :Text;
  inputTokens      @3 :UInt32;
  outputTokens     @4 :UInt32;
  thinkingLevel    @5 :UInt32;
  statusCode       @6 :UInt32;
  durationMs       @7 :UInt64;
  cacheReadTokens  @8 :UInt32;
  cacheWriteTokens @9 :UInt32;
}

struct StreamChunkEvent {
  accountId  @0 :Text;
  chunkIndex @1 :UInt32;
  eventType  @2 :Text;
  data       @3 :Text;
}

# 思考层级覆盖，noOverride 表示不干预
enum ThinkingLevelOverride {
  noOverride @0;
  disabled   @1;
  low        @2;
  medium     @3;
  high       @4;
  xhigh      @5;
}

# 路由结果（routed / rejected 二选一）
struct RouteResult {
  union {
    routed :group {
      accountId             @0 :Text;
      modelOverride         @1 :Text;
      thinkingLevelOverride @2 :ThinkingLevelOverride;
      # true 时代理端跳过 billing header suffix 哈希校验；适用于非 Claude Code 原生客户端
      skipBillingCheck      @5 :Bool;
    }
    rejected :group {
      statusCode @3 :UInt16;
      message    @4 :Text;
    }
  }
}

# 账号生命周期事件类型
enum AccountEventKind {
  added         @0;
  removed       @1;
  refreshed     @2;
  configUpdated @3;
}

# 决策端实现此 capability，代理端持有并主动调用
interface Router {
  routeRequest @0 (
    requestId       :Text,
    apiKey          :Text,
    model           :Text,
    endpoint        :Text,
    userAgent       :Text,
    # Claude Code 进程级会话 ID（来自 x-claude-code-session-id 头），
    # 同一 Claude Code 进程的所有请求共享此值，可用于决策端实现粘性路由。
    # 空字符串表示客户端未携带该头。
    sessionId       :Text,
    # 单次请求 ID（来自 x-client-request-id 头），每个 HTTP 请求独立。
    # 空字符串表示客户端未携带该头。
    clientRequestId :Text,
  ) -> (result :RouteResult);

  reportUsage @1 (requestId :Text, report :UsageReport) -> ();
  reportChunk @2 (requestId :Text, chunk :StreamChunkEvent) -> ();
  onAccountEvent @3 (accountId :Text, kind :AccountEventKind) -> ();
}

interface PolicyService {
  # 决策端注册自己的 Router capability 到代理端
  connect @0 (router :Router) -> ();
}
