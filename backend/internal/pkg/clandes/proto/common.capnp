@0xa0b1c2d3e4f5a6b7;

using Go = import "/go.capnp";
$Go.package("proto");
$Go.import("github.com/Wei-Shaw/sub2api/internal/pkg/clandes/proto");

struct ProxyInfo {
  ip             @0 :Text;
  country        @1 :Text;
  region         @2 :Text;
  city           @3 :Text;
  continent      @4 :Text;
  asn            @5 :UInt32;
  asOrganization @6 :Text;
  colo           @7 :Text;
  timezone       @8 :Text;
}

struct ProbeTiming {
  clientBuildUs  @0 :UInt64;   # wreq client 构建耗时 (μs)
  requestSendMs  @1 :UInt64;   # proxy connect + TLS + HTTP 往返到收到 headers (ms)
  bodyReadUs     @2 :UInt64;   # 读取响应 body (μs)
  jsonParseUs    @3 :UInt64;   # JSON 反序列化 (μs)
  totalMs        @4 :UInt64;   # 端到端总耗时 (ms)
  bodyLen        @5 :UInt64;   # 响应 body 字节数
}
