@0xa6b7c8d9e0f1a2b3;

using Go = import "/go.capnp";
$Go.package("proto");
$Go.import("github.com/Wei-Shaw/sub2api/internal/pkg/clandes/proto");

using Account  = import "account.capnp";
using Auth     = import "claude_auth.capnp";
using Query    = import "claude_query.capnp";
using Proxy    = import "proxy.capnp";
using Policy = import "callback.capnp";

# 根 capability：客户端连接后先调用 auth 拿到 ClandesService
interface Bootstrap {
  # 无需鉴权时 token 传空字符串
  auth @0 (token :Text) -> (service :ClandesService);
}

interface ClandesService {
  accountService    @0 () -> (svc :Account.AccountService);
  claudeAuthService @1 () -> (svc :Auth.ClaudeAuthService);
  claudeQueryService @2 () -> (svc :Query.ClaudeQueryService);
  proxyService      @3 () -> (svc :Proxy.ProxyService);
  policyService     @4 () -> (svc :Policy.PolicyService);
  getVersion        @5 () -> (version :Text);
}
