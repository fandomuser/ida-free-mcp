// Loopback-only TCP transport for the idamcp bridge (newline-delimited JSON).
//
// Deliberately free of IDA SDK headers. Thread creation is injected through
// ThreadOps so the plugin can use qthreads (required to cancel pending
// execute_sync() requests on shutdown) while tests can use std::thread.
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace idamcp {

struct ConnState
{
  bool authenticated = false;
  uint64_t id = 0;
};

struct ThreadOps
{
  // Starts `fn` on a new thread and returns an opaque handle (nullptr on failure).
  std::function<void *(std::function<void()> fn)> spawn;
  // Called from the stopping thread before join: must unblock the thread if it
  // is waiting on the host application (e.g. cancel execute_sync requests).
  std::function<void(void *handle)> cancel;
  // Joins and frees the thread.
  std::function<void(void *handle)> join;
};

struct TransportConfig
{
  uint16_t port = 0;                     // 0 = ephemeral
  size_t max_line_bytes = 1u << 20;      // 1 MiB per request line
  int max_connections = 8;
  int auth_timeout_ms = 10000;           // unauthenticated connections are dropped after this
};

// Handles one request line; returns the response line (without trailing '\n').
// Called on a connection thread.
using LineHandler = std::function<std::string(const std::string &line, ConnState &st)>;
using LogFn = std::function<void(const std::string &msg)>;

class Transport
{
public:
  Transport(TransportConfig cfg, ThreadOps ops, LineHandler handler, LogFn log);
  ~Transport();
  Transport(const Transport &) = delete;
  Transport &operator=(const Transport &) = delete;

  // Binds 127.0.0.1:<port> and starts accepting. Returns false and sets *err on failure.
  bool start(std::string *err);
  // Stops accepting, closes all connections, unblocks and joins all threads. Idempotent.
  void stop();
  uint16_t port() const { return port_; }
  bool stopping() const { return stopping_.load(); }

private:
  struct Conn;
  void accept_loop();
  void serve(std::shared_ptr<Conn> c);

  TransportConfig cfg_;
  ThreadOps ops_;
  LineHandler handler_;
  LogFn log_;
  uintptr_t listen_sock_;
  uint16_t port_ = 0;
  void *accept_thread_ = nullptr;
  std::atomic<bool> stopping_{false};
  std::atomic<uint64_t> next_id_{1};
  std::mutex mu_;
  std::vector<std::shared_ptr<Conn>> conns_;
  bool wsa_ok_ = false;
};

}  // namespace idamcp
