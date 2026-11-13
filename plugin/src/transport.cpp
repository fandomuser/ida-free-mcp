#include "transport.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>

namespace idamcp {

struct Transport::Conn
{
  std::atomic<SOCKET> sock{INVALID_SOCKET};
  std::atomic<bool> done{false};
  void *thread = nullptr;
  ConnState state;

  void close_once()
  {
    SOCKET s = sock.exchange(INVALID_SOCKET);
    if ( s != INVALID_SOCKET )
    {
      ::shutdown(s, SD_BOTH);
      ::closesocket(s);
    }
  }
};

Transport::Transport(TransportConfig cfg, ThreadOps ops, LineHandler handler, LogFn log)
  : cfg_(cfg), ops_(std::move(ops)), handler_(std::move(handler)), log_(std::move(log)),
    listen_sock_(static_cast<uintptr_t>(INVALID_SOCKET))
{
}

Transport::~Transport()
{
  stop();
}

static std::string wsa_error(const char *what)
{
  return std::string(what) + " failed (WSA error " + std::to_string(::WSAGetLastError()) + ")";
}

bool Transport::start(std::string *err)
{
  WSADATA wsa;
  if ( ::WSAStartup(MAKEWORD(2, 2), &wsa) != 0 )
  {
    *err = "WSAStartup failed";
    return false;
  }
  wsa_ok_ = true;

  SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if ( s == INVALID_SOCKET )
  {
    *err = wsa_error("socket");
    return false;
  }
  // Prevent other processes from hijacking the port (Windows-specific).
  BOOL excl = TRUE;
  ::setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char *>(&excl), sizeof(excl));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(cfg_.port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1 only, never 0.0.0.0
  if ( ::bind(s, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0 )
  {
    *err = wsa_error("bind(127.0.0.1)");
    ::closesocket(s);
    return false;
  }
  if ( ::listen(s, 8) != 0 )
  {
    *err = wsa_error("listen");
    ::closesocket(s);
    return false;
  }
  int alen = sizeof(addr);
  ::getsockname(s, reinterpret_cast<sockaddr *>(&addr), &alen);
  port_ = ntohs(addr.sin_port);
  listen_sock_ = static_cast<uintptr_t>(s);

  accept_thread_ = ops_.spawn([this] { accept_loop(); });
  if ( accept_thread_ == nullptr )
  {
    *err = "failed to start accept thread";
    ::closesocket(s);
    listen_sock_ = static_cast<uintptr_t>(INVALID_SOCKET);
    return false;
  }
  return true;
}

void Transport::accept_loop()
{
  const SOCKET ls = static_cast<SOCKET>(listen_sock_);
  while ( !stopping_.load() )
  {
    sockaddr_in peer{};
    int plen = sizeof(peer);
    SOCKET cs = ::accept(ls, reinterpret_cast<sockaddr *>(&peer), &plen);
    if ( cs == INVALID_SOCKET )
    {
      if ( stopping_.load() )
        break;
      log_(wsa_error("accept"));
      ::Sleep(100);
      continue;
    }
    // Defence in depth: the socket is bound to loopback, but verify the peer anyway.
    if ( peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK) )
    {
      ::closesocket(cs);
      continue;
    }

    std::vector<std::shared_ptr<Conn>> finished;
    std::shared_ptr<Conn> c;
    {
      std::lock_guard<std::mutex> lk(mu_);
      // Reap finished connections.
      auto it = std::partition(conns_.begin(), conns_.end(),
                               [](const std::shared_ptr<Conn> &x) { return !x->done.load(); });
      finished.assign(it, conns_.end());
      conns_.erase(it, conns_.end());

      if ( static_cast<int>(conns_.size()) >= cfg_.max_connections )
      {
        static const char busy[] =
          "{\"id\":null,\"ok\":false,\"error\":{\"code\":\"busy\",\"message\":\"too many connections\"}}\n";
        ::send(cs, busy, static_cast<int>(sizeof(busy) - 1), 0);
        ::closesocket(cs);
      }
      else
      {
        c = std::make_shared<Conn>();
        c->sock.store(cs);
        c->state.id = next_id_.fetch_add(1);
        DWORD tmo = static_cast<DWORD>(cfg_.auth_timeout_ms);
        ::setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&tmo), sizeof(tmo));
        c->thread = ops_.spawn([this, c] { serve(c); });
        if ( c->thread == nullptr )
        {
          c->close_once();
          c.reset();
        }
        else
        {
          conns_.push_back(c);
        }
      }
    }
    for ( auto &f : finished )
      ops_.join(f->thread);
  }
}

static bool send_all(SOCKET s, const std::string &data)
{
  size_t off = 0;
  while ( off < data.size() )
  {
    const int chunk = static_cast<int>(std::min<size_t>(data.size() - off, 1u << 20));
    const int n = ::send(s, data.data() + off, chunk, 0);
    if ( n <= 0 )
      return false;
    off += static_cast<size_t>(n);
  }
  return true;
}

void Transport::serve(std::shared_ptr<Conn> c)
{
  std::string buf;
  char chunk[16384];
  bool was_authed = false;
  while ( !stopping_.load() )
  {
    const SOCKET s = c->sock.load();
    if ( s == INVALID_SOCKET )
      break;
    const int n = ::recv(s, chunk, sizeof(chunk), 0);
    if ( n <= 0 )
      break;  // closed, error, or auth timeout
    buf.append(chunk, static_cast<size_t>(n));

    size_t nl;
    bool fatal = false;
    while ( (nl = buf.find('\n')) != std::string::npos )
    {
      std::string line = buf.substr(0, nl);
      buf.erase(0, nl + 1);
      if ( !line.empty() && line.back() == '\r' )
        line.pop_back();
      if ( line.empty() )
        continue;
      std::string resp = handler_(line, c->state);
      resp += '\n';
      const SOCKET s2 = c->sock.load();
      if ( s2 == INVALID_SOCKET || !send_all(s2, resp) )
      {
        fatal = true;
        break;
      }
      if ( !was_authed && c->state.authenticated )
      {
        was_authed = true;
        DWORD tmo = 0;  // no idle timeout once authenticated
        ::setsockopt(s2, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&tmo), sizeof(tmo));
      }
    }
    if ( fatal )
      break;
    if ( buf.size() > cfg_.max_line_bytes )
    {
      const SOCKET s3 = c->sock.load();
      if ( s3 != INVALID_SOCKET )
        send_all(s3, "{\"id\":null,\"ok\":false,\"error\":{\"code\":\"request_too_large\","
                     "\"message\":\"request line exceeds limit\"}}\n");
      break;
    }
  }
  // Mark finished BEFORE closing: once the peer sees EOF, this slot must already be
  // reclaimable, or a client reconnecting immediately can be refused as "busy".
  // (Reaping only joins the thread, which waits for this function to return.)
  c->done.store(true);
  c->close_once();
}

void Transport::stop()
{
  if ( stopping_.exchange(true) )
    return;
  const SOCKET ls = static_cast<SOCKET>(listen_sock_);
  if ( ls != INVALID_SOCKET )
  {
    ::closesocket(ls);
    listen_sock_ = static_cast<uintptr_t>(INVALID_SOCKET);
  }
  if ( accept_thread_ != nullptr )
  {
    ops_.join(accept_thread_);
    accept_thread_ = nullptr;
  }
  std::vector<std::shared_ptr<Conn>> conns;
  {
    std::lock_guard<std::mutex> lk(mu_);
    conns.swap(conns_);
  }
  for ( auto &c : conns )
  {
    c->close_once();
    ops_.cancel(c->thread);
  }
  for ( auto &c : conns )
    ops_.join(c->thread);
  if ( wsa_ok_ )
  {
    ::WSACleanup();
    wsa_ok_ = false;
  }
}

}  // namespace idamcp
