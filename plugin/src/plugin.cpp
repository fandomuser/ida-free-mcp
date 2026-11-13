// idamcp bridge: IDA plugin entry point, authentication and request dispatch.
//
// Lifecycle: the plugin is a PLUGIN_MULTI module without PLUGIN_FIX, so IDA
// creates one bridge_t per opened database and destroys it when the database
// closes. The bridge starts OFF; running the plugin (Edit > Plugins > idamcp)
// toggles it. While ON it listens on 127.0.0.1 (ephemeral port) and publishes
// {port, token} in %LOCALAPPDATA%\idamcp\instances\ida-<pid>.json, readable
// only by the current user. Clients must present the token first.
//
// Threading: socket I/O runs on qthreads; every database access is marshalled
// to IDA's main thread with execute_sync(MFF_READ / MFF_WRITE). On shutdown,
// set_execute_sync_availability(esa_unavailable) cancels any request a worker
// is still waiting on, so unloading can never deadlock.

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>

#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <nalt.hpp>

#include "handlers.hpp"
#include "json.hpp"
#include "platform.hpp"
#include "transport.hpp"
#include "version.hpp"

using namespace idamcp;
using mj::Value;

namespace {

constexpr int64_t kDefaultTimeoutMs = 15000;
constexpr int64_t kMaxTimeoutMs = 120000;

//--------------------------------------------------------------------------
// qthread-backed ThreadOps
struct qthread_box_t
{
  qthread_t t = nullptr;
  std::function<void()> fn;
};

int idaapi thread_trampoline(void *ud)
{
  static_cast<qthread_box_t *>(ud)->fn();
  return 0;
}

ThreadOps make_qthread_ops()
{
  ThreadOps ops;
  ops.spawn = [](std::function<void()> fn) -> void * {
    auto *box = new qthread_box_t;
    box->fn = std::move(fn);
    box->t = qthread_create(thread_trampoline, box);
    if ( box->t == nullptr )
    {
      delete box;
      return nullptr;
    }
    return box;
  };
  ops.cancel = [](void *h) {
    if ( h != nullptr )
      set_execute_sync_availability(static_cast<qthread_box_t *>(h)->t, esa_unavailable);
  };
  ops.join = [](void *h) {
    if ( h == nullptr )
      return;
    auto *box = static_cast<qthread_box_t *>(h);
    qthread_join(box->t);
    set_execute_sync_availability(box->t, esa_release);
    qthread_free(box->t);
    delete box;
  };
  return ops;
}

//--------------------------------------------------------------------------
// Runs one handler on the main thread.
struct exec_t : public exec_request_t
{
  const MethodDef *m;
  const Value &params;
  std::chrono::steady_clock::time_point deadline;
  bool ran = false;
  bool expired_before_start = false;
  Value result;
  std::string err_code;
  std::string err_msg;

  exec_t(const MethodDef *_m, const Value &_p, std::chrono::steady_clock::time_point _d)
    : m(_m), params(_p), deadline(_d) {}

  ssize_t idaapi execute() override
  {
    // Never start work (especially writes) the client has already given up on.
    if ( std::chrono::steady_clock::now() >= deadline )
    {
      expired_before_start = true;
      return 0;
    }
    ran = true;
    // Unattended mode while serving the request: any IDA API that would pop a
    // dialog gets its default answer instead of blocking the UI thread.
    struct batch_guard_t
    {
      bool old = batch;
      batch_guard_t() { batch = true; }
      ~batch_guard_t() { batch = old; }
    } batch_guard;
    try
    {
      Call call{params, deadline};
      result = m->fn(call);
    }
    catch ( const BridgeError &e )
    {
      err_code = e.code;
      err_msg = e.message;
    }
    catch ( const std::exception &e )
    {
      err_code = "internal_error";
      err_msg = e.what();
    }
    catch ( ... )
    {
      err_code = "internal_error";
      err_msg = "unexpected exception in handler";
    }
    return 0;
  }
};

//--------------------------------------------------------------------------
struct bridge_t : public plugmod_t
{
  // Owned and replaced only on IDA's main thread (constructor, run(), destructor).
  std::unique_ptr<Transport> transport;
  std::string token;            // fresh for every activation
  std::string discovery_path;
  std::string log_path;
  std::mutex log_mu;
  // Read by socket threads; true only while the bridge is fully up.
  std::atomic<bool> active{false};
  bool usable = false;          // state dir available
  // Captured on the main thread in the constructor: hello_info() runs on socket
  // threads, where IDA APIs such as get_path()/get_kernel_version() are not safe.
  std::string ida_version;
  std::string idb_path;
  std::string input_file;

  bridge_t();
  ~bridge_t() override;
  bool idaapi run(size_t) override;

  bool start_bridge();
  void stop_bridge(const char *reason);
  std::string handle_line(const std::string &line, ConnState &st);
  void log_event(const Value &ev);
  Value hello_info() const;
};

std::string error_response(const Value &id, const std::string &code, const std::string &message)
{
  Value err = Value::object();
  err.set("code", code);
  err.set("message", message);
  Value r = Value::object();
  r.set("id", id);
  r.set("ok", false);
  r.set("error", std::move(err));
  return r.dump();
}

std::string ok_response(const Value &id, Value result)
{
  Value r = Value::object();
  r.set("id", id);
  r.set("ok", true);
  r.set("result", std::move(result));
  return r.dump();
}

// The plugin is loaded with every database, but the bridge stays OFF until the
// user turns it on via Edit > Plugins > idamcp. Nothing listens before that.
bridge_t::bridge_t()
{
  char ver[64] = {0};
  get_kernel_version(ver, sizeof(ver));
  ida_version = ver;
  const char *ip = get_path(PATH_TYPE_IDB);
  idb_path = ip != nullptr ? ip : "";
  char in[QMAXPATH] = {0};
  get_input_file_path(in, sizeof(in));
  input_file = in;

  const std::string dir = platform::state_dir();
  if ( dir.empty() )
  {
    msg("[idamcp] ERROR: %%LOCALAPPDATA%%\\idamcp is not available; MCP cannot be enabled\n");
    return;
  }
  const std::string inst_dir = dir + "\\instances";
  const std::string logs_dir = dir + "\\logs";
  platform::make_dirs(inst_dir);
  platform::make_dirs(logs_dir);
  const uint32_t pid = platform::current_pid();
  discovery_path = inst_dir + "\\ida-" + std::to_string(pid) + ".json";
  log_path = logs_dir + "\\bridge-" + std::to_string(pid) + ".log";
  usable = true;
  // A discovery file left behind by a crashed earlier process with this pid must not advertise us.
  platform::remove_file(discovery_path);
  msg("[idamcp] MCP DISABLED (turn on via Edit > Plugins > idamcp)\n");
}

bool bridge_t::start_bridge()
{
  if ( !usable )
    return false;
  token = platform::random_hex(32);
  if ( token.empty() )
  {
    msg("[idamcp] ERROR: could not generate an authentication token; MCP stays DISABLED\n");
    return false;
  }
  TransportConfig cfg;
  qstring port_s;
  if ( qgetenv("IDAMCP_PORT", &port_s) )
  {
    const long p = strtol(port_s.c_str(), nullptr, 10);
    if ( p > 0 && p < 65536 )
      cfg.port = static_cast<uint16_t>(p);
  }
  transport = std::make_unique<Transport>(
    cfg, make_qthread_ops(),
    [this](const std::string &line, ConnState &st) { return handle_line(line, st); },
    [this](const std::string &m) {
      Value ev = Value::object();
      ev.set("level", "warning");
      ev.set("event", "transport");
      ev.set("message", m);
      log_event(ev);
    });
  std::string err;
  if ( !transport->start(&err) )
  {
    msg("[idamcp] ERROR: could not start the bridge: %s. MCP stays DISABLED\n", err.c_str());
    transport.reset();
    token.clear();
    return false;
  }
  // Accept requests before advertising, so a client that finds the discovery
  // file never meets a half-initialised bridge.
  active.store(true);

  Value disc = Value::object();
  disc.set("pid", static_cast<int64_t>(platform::current_pid()));
  disc.set("host", "127.0.0.1");
  disc.set("port", static_cast<int64_t>(transport->port()));
  disc.set("token", token);
  disc.set("protocol", IDAMCP_PROTOCOL);
  disc.set("bridge_version", IDAMCP_VERSION);
  disc.set("idb_path", idb_path);
  disc.set("input_file", input_file);
  disc.set("started_at", platform::utc_now_iso8601());
  if ( !platform::write_file_atomic(discovery_path, disc.dump()) )
  {
    msg("[idamcp] ERROR: could not write %s. MCP stays DISABLED\n", discovery_path.c_str());
    active.store(false);
    transport->stop();
    transport.reset();
    token.clear();
    return false;
  }
  Value ev = Value::object();
  ev.set("level", "info");
  ev.set("event", "started");
  ev.set("port", static_cast<int64_t>(transport->port()));
  log_event(ev);
  msg("[idamcp] MCP ENABLED \xE2\x80\x94 read/write available\n");
  return true;
}

// Stops everything and leaves the database untouched. Runs on the main thread,
// so no handler can be mid-execution; workers waiting in execute_sync() are
// cancelled by Transport::stop() and their requests are never run.
void bridge_t::stop_bridge(const char *reason)
{
  if ( !transport )
    return;
  active.store(false);                        // refuse new requests immediately
  if ( !discovery_path.empty() )
    platform::remove_file(discovery_path);    // stop advertising before tearing down
  transport->stop();                          // close listener + clients, cancel pending, join threads
  transport.reset();                          // release sockets / Winsock
  token.clear();
  Value ev = Value::object();
  ev.set("level", "info");
  ev.set("event", "stopped");
  ev.set("reason", reason);
  log_event(ev);
}

bridge_t::~bridge_t()
{
  if ( transport )
  {
    stop_bridge("database closed");
    msg("[idamcp] MCP DISABLED\n");
  }
}

bool idaapi bridge_t::run(size_t)
{
  if ( transport )
  {
    stop_bridge("user");
    msg("[idamcp] MCP DISABLED\n");
  }
  else if ( !start_bridge() )
  {
    warning("idamcp: MCP could not be enabled; see the Output window for details.");
  }
  return true;
}

void bridge_t::log_event(const Value &ev)
{
  if ( log_path.empty() )
    return;
  Value line = Value::object();
  line.set("ts", platform::utc_now_iso8601());
  for ( const auto &kv : ev.as_object() )
    line.set(kv.first, kv.second);
  std::lock_guard<std::mutex> lk(log_mu);
  platform::append_line(log_path, line.dump());
}

Value bridge_t::hello_info() const
{
  Value o = Value::object();
  o.set("bridge_version", IDAMCP_VERSION);
  o.set("protocol", IDAMCP_PROTOCOL);
  o.set("pid", static_cast<int64_t>(platform::current_pid()));
  o.set("ida_version", ida_version);
  o.set("idb_path", idb_path);
  o.set("methods", describe_methods());
  // Explicit capability report: this bridge only exposes what IDA Free's SDK
  // genuinely provides. It never produces pseudocode.
  Value caps = Value::object();
  caps.set("disassembly", true);
  caps.set("xrefs", true);
  caps.set("flowchart", true);
  caps.set("strings", true);
  caps.set("byte_search", true);
  caps.set("database_writes", true);
  caps.set("decompiler", false);
  caps.set("scripting", false);
  o.set("capabilities", std::move(caps));
  return o;
}

std::string bridge_t::handle_line(const std::string &line, ConnState &st)
{
  Value req;
  try
  {
    req = mj::parse(line);
  }
  catch ( const mj::ParseError &e )
  {
    return error_response(Value(), "parse_error", e.what());
  }
  if ( !req.is_object() )
    return error_response(Value(), "invalid_request", "request must be a JSON object");
  Value id;
  if ( const Value *idv = req.find("id") )
    id = *idv;
  const Value *mv = req.find("method");
  if ( mv == nullptr || !mv->is_string() )
    return error_response(id, "invalid_request", "missing string field 'method'");
  const std::string method = mv->as_string();
  Value params = Value::object();
  if ( const Value *pv = req.find("params") )
  {
    if ( pv->is_object() )
      params = *pv;
    else if ( !pv->is_null() )
      return error_response(id, "invalid_request", "'params' must be an object");
  }

  if ( !active.load() )
    return error_response(id, "disabled", "MCP was turned off in IDA (Edit > Plugins > idamcp)");
  if ( !st.authenticated )
  {
    if ( method != "hello" )
      return error_response(id, "unauthenticated", "first request must be 'hello' with the token");
    const Value *tv = params.find("token");
    if ( tv == nullptr || !tv->is_string() || !platform::constant_time_equals(tv->as_string(), token) )
    {
      Value ev = Value::object();
      ev.set("level", "warning");
      ev.set("event", "auth_failed");
      ev.set("conn", static_cast<int64_t>(st.id));
      log_event(ev);
      return error_response(id, "unauthenticated", "invalid token");
    }
    st.authenticated = true;
    return ok_response(id, hello_info());
  }
  if ( method == "hello" )
    return ok_response(id, hello_info());
  if ( method == "ping" )
  {
    Value o = Value::object();
    o.set("pong", true);
    return ok_response(id, std::move(o));
  }

  const MethodDef *m = find_method(method);
  if ( m == nullptr )
    return error_response(id, "unknown_method", "unknown method '" + method + "'");
  int64_t timeout_ms = kDefaultTimeoutMs;
  if ( const Value *tv = params.find("timeout_ms") )
  {
    if ( !tv->is_int() || tv->as_int() < 100 || tv->as_int() > kMaxTimeoutMs )
      return error_response(id, "invalid_params", "timeout_ms must be an integer in [100, 120000]");
    timeout_ms = tv->as_int();
  }
  if ( !active.load() )
    return error_response(id, "disabled", "MCP was turned off in IDA (Edit > Plugins > idamcp)");

  const auto t0 = std::chrono::steady_clock::now();
  exec_t req_exec(m, params, t0 + std::chrono::milliseconds(timeout_ms));
  execute_sync(req_exec, m->write ? MFF_WRITE : MFF_READ);
  const int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();

  std::string resp;
  std::string code;
  if ( req_exec.expired_before_start )
  {
    code = "timeout";
    resp = error_response(id, code, "IDA's main thread was busy (modal dialog or long analysis?) and the "
                                    "request expired before it started; nothing was executed");
  }
  else if ( !req_exec.ran )
  {
    code = "cancelled";
    resp = error_response(id, code, "request was cancelled because MCP was turned off or the database closed");
  }
  else if ( !req_exec.err_code.empty() )
  {
    code = req_exec.err_code;
    resp = error_response(id, code, req_exec.err_msg);
  }
  else
  {
    resp = ok_response(id, std::move(req_exec.result));
  }
  Value ev = Value::object();
  ev.set("level", code.empty() ? "info" : "warning");
  ev.set("event", "request");
  ev.set("conn", static_cast<int64_t>(st.id));
  ev.set("method", method);
  ev.set("ms", ms);
  ev.set("ok", code.empty());
  if ( !code.empty() )
    ev.set("error", code);
  log_event(ev);
  return resp;
}

//--------------------------------------------------------------------------
plugmod_t *idaapi init()
{
  return new bridge_t;
}

}  // namespace

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,                    // one bridge per database; unloaded when it closes
  init,
  nullptr,
  nullptr,
  "Turn the MCP bridge for this database ON/OFF (read/write for MCP clients such as Claude Code)",
  "Each run toggles the loopback-only bridge used by the idamcp MCP server.\n"
  "It starts OFF for every database; while ON, connected clients can read and modify it.",
  "idamcp",
  nullptr,
};
