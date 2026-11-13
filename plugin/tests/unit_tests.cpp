// Standalone unit tests for the bridge's IDA-independent components:
// JSON parsing/serialisation and the loopback transport.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>

#include "json.hpp"
#include "platform.hpp"
#include "transport.hpp"

static int g_failures = 0;
static int g_checks = 0;

// Reports file:line only. Stringifying the expression (#cond) breaks older MSVC
// preprocessors when it contains raw string literals or \u escapes.
#define CHECK(cond)                                                                 \
  do {                                                                              \
    g_checks++;                                                                     \
    if ( !(cond) ) {                                                                \
      g_failures++;                                                                 \
      std::fprintf(stderr, "FAIL %s:%d\n", __FILE__, __LINE__);                     \
    }                                                                               \
  } while ( 0 )

static bool parse_fails(const std::string &s)
{
  try { mj::parse(s); return false; } catch ( const mj::ParseError & ) { return true; }
}

static void test_json()
{
  // Round trips
  const mj::Value v = mj::parse(R"({"a":1,"b":[true,false,null],"c":"x\"y\\z","d":-2.5,"e":{}})");
  CHECK(v.is_object());
  CHECK(v.find("a")->as_int() == 1);
  CHECK(v.find("b")->as_array().size() == 3);
  CHECK(v.find("c")->as_string() == "x\"y\\z");
  CHECK(v.find("d")->as_double() == -2.5);
  CHECK(v.find("missing") == nullptr);
  CHECK(v.dump() == R"({"a":1,"b":[true,false,null],"c":"x\"y\\z","d":-2.5,"e":{}})");

  // Escapes and unicode (incl. surrogate pairs)
  CHECK(mj::parse(R"("é\n\t")").as_string() == "\xC3\xA9\n\t");
  CHECK(mj::parse(R"("😀")").as_string() == "\xF0\x9F\x98\x80");
  CHECK(parse_fails(R"("\ud83d")"));
  CHECK(parse_fails(R"("\ude00")"));

  // int64 range and big numbers
  CHECK(mj::parse("9223372036854775807").as_int() == INT64_MAX);
  CHECK(mj::parse("18446744073709551615").type() == mj::Type::Double);

  // Malformed input
  CHECK(parse_fails(""));
  CHECK(parse_fails("{"));
  CHECK(parse_fails("{\"a\":1,}"));
  CHECK(parse_fails("[1 2]"));
  CHECK(parse_fails("01"));
  CHECK(parse_fails("1."));
  CHECK(parse_fails("tru"));
  CHECK(parse_fails("\"a\nb\""));
  CHECK(parse_fails("{} extra"));

  // Depth limit
  std::string deep(100, '[');
  deep += std::string(100, ']');
  CHECK(parse_fails(deep));
  CHECK(!parse_fails(std::string(10, '[') + std::string(10, ']')));

  // Serializer sanitises invalid UTF-8 and control chars
  mj::Value s(std::string("ok\x01\xFF\xC3\xA9"));
  CHECK(s.dump() == "\"ok\\u0001\xEF\xBF\xBD\xC3\xA9\"");
  // Overlong encoding of '/' must be rejected (replaced)
  mj::Value ov(std::string("\xC0\xAF"));
  CHECK(ov.dump() == "\"\xEF\xBF\xBD\xEF\xBF\xBD\"");

  // set() replaces existing keys, keeps order
  mj::Value o = mj::Value::object();
  o.set("x", 1);
  o.set("y", 2);
  o.set("x", 3);
  CHECK(o.dump() == R"({"x":3,"y":2})");
}

static void test_platform()
{
  const std::string a = idamcp::platform::random_hex(32);
  const std::string b = idamcp::platform::random_hex(32);
  CHECK(a.size() == 64);
  CHECK(a != b);
  CHECK(idamcp::platform::constant_time_equals("abc", "abc"));
  CHECK(!idamcp::platform::constant_time_equals("abc", "abd"));
  CHECK(!idamcp::platform::constant_time_equals("abc", "ab"));
  CHECK(idamcp::platform::utc_now_iso8601().size() == 24);
}

// ---- transport ----------------------------------------------------------------
static idamcp::ThreadOps std_ops()
{
  idamcp::ThreadOps ops;
  ops.spawn = [](std::function<void()> fn) -> void * { return new std::thread(std::move(fn)); };
  ops.cancel = [](void *) {};
  ops.join = [](void *h) {
    auto *t = static_cast<std::thread *>(h);
    if ( t->joinable() ) t->join();
    delete t;
  };
  return ops;
}

static SOCKET connect_to(uint16_t port)
{
  SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if ( ::connect(s, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0 )
  {
    ::closesocket(s);
    return INVALID_SOCKET;
  }
  DWORD tmo = 5000;
  ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&tmo), sizeof(tmo));
  return s;
}

static std::string read_line(SOCKET s)
{
  std::string out;
  char ch;
  while ( ::recv(s, &ch, 1, 0) == 1 )
  {
    if ( ch == '\n' )
      return out;
    out += ch;
  }
  return out + "<EOF>";
}

static void send_str(SOCKET s, const std::string &d)
{
  ::send(s, d.data(), static_cast<int>(d.size()), 0);
}

static void test_transport()
{
  WSADATA wsa;
  ::WSAStartup(MAKEWORD(2, 2), &wsa);
  idamcp::TransportConfig cfg;
  cfg.max_line_bytes = 1024;
  cfg.max_connections = 2;
  cfg.auth_timeout_ms = 500;
  idamcp::Transport tr(cfg, std_ops(),
    [](const std::string &line, idamcp::ConnState &st) -> std::string {
      if ( line == "auth" ) { st.authenticated = true; return "authed"; }
      return "echo:" + line;
    },
    [](const std::string &) {});
  std::string err;
  CHECK(tr.start(&err));
  CHECK(tr.port() != 0);

  // Request/response, CRLF tolerance, pipelining
  SOCKET c = connect_to(tr.port());
  CHECK(c != INVALID_SOCKET);
  send_str(c, "auth\nhello\r\nworld\n");
  CHECK(read_line(c) == "authed");
  CHECK(read_line(c) == "echo:hello");
  CHECK(read_line(c) == "echo:world");

  // Unauthenticated connection is dropped after auth timeout
  SOCKET idle = connect_to(tr.port());
  CHECK(idle != INVALID_SOCKET);
  CHECK(read_line(idle) == "<EOF>");
  ::closesocket(idle);

  // Oversized line is rejected and the connection closed
  SOCKET big = connect_to(tr.port());
  send_str(big, "auth\n");
  CHECK(read_line(big) == "authed");
  send_str(big, std::string(4096, 'x'));
  const std::string resp = read_line(big);
  CHECK(resp.find("request_too_large") != std::string::npos);
  ::closesocket(big);

  // Authenticated connection survives longer than the auth timeout
  ::Sleep(700);
  send_str(c, "still-here\n");
  CHECK(read_line(c) == "echo:still-here");

  // stop() closes live connections and returns (no hang)
  tr.stop();
  CHECK(read_line(c) == "<EOF>");
  ::closesocket(c);
  CHECK(connect_to(tr.port()) == INVALID_SOCKET);
  ::WSACleanup();
}

// The plugin creates a fresh Transport on every ON and destroys it on OFF.
// Repeated cycles must not leak sockets, threads or Winsock initialisation.
static void test_transport_restart_cycles()
{
  WSADATA wsa;
  ::WSAStartup(MAKEWORD(2, 2), &wsa);
  std::atomic<int> live_threads{0};
  idamcp::ThreadOps ops = std_ops();
  auto spawn = ops.spawn;
  ops.spawn = [&live_threads, spawn](std::function<void()> fn) -> void * {
    return spawn([&live_threads, fn] { live_threads++; fn(); live_threads--; });
  };
  uint16_t prev_port = 0;
  for ( int i = 0; i < 25; i++ )
  {
    idamcp::Transport tr(idamcp::TransportConfig{}, ops,
      [](const std::string &line, idamcp::ConnState &st) -> std::string {
        st.authenticated = true;
        return "ok:" + line;
      },
      [](const std::string &) {});
    std::string err;
    CHECK(tr.start(&err));
    SOCKET c = connect_to(tr.port());
    CHECK(c != INVALID_SOCKET);
    send_str(c, "ping\n");
    CHECK(read_line(c) == "ok:ping");
    prev_port = tr.port();
    tr.stop();                         // with a live client connected
    CHECK(read_line(c) == "<EOF>");
    ::closesocket(c);
    CHECK(connect_to(prev_port) == INVALID_SOCKET);
  }
  CHECK(live_threads.load() == 0);
  ::WSACleanup();
}

int main()
{
  test_json();
  test_platform();
  test_transport();
  test_transport_restart_cycles();
  std::printf("%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
