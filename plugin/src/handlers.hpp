// IDA-side request handlers. All handlers run on IDA's main thread (via
// execute_sync) and must bound their own work using Call::expired().
#pragma once

#include <chrono>
#include <string>

#include "json.hpp"

namespace idamcp {

struct BridgeError
{
  std::string code;     // stable machine-readable code, e.g. "not_found"
  std::string message;  // actionable, human/LLM-readable message
};

struct Call
{
  const mj::Value &params;
  std::chrono::steady_clock::time_point deadline;
  bool expired() const { return std::chrono::steady_clock::now() >= deadline; }
};

using HandlerFn = mj::Value (*)(Call &call);

struct MethodDef
{
  const char *name;
  HandlerFn fn;
  bool write;  // modifies the database (gated, executed with MFF_WRITE)
};

// Returns nullptr for unknown methods.
const MethodDef *find_method(const std::string &name);
// All registered methods (for the hello/capabilities response).
mj::Value describe_methods();

}  // namespace idamcp
