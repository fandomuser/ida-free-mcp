// Minimal, dependency-free JSON value + parser + serializer for the idamcp bridge.
//
// Scope: exactly what the bridge protocol needs (RFC 8259 objects, arrays,
// strings with full escape/surrogate handling, int64/double numbers, bools,
// null). The serializer always emits valid UTF-8: invalid byte sequences
// coming from the IDA database are replaced with U+FFFD.
//
// This file must not include any IDA SDK header (it is unit-tested standalone).
#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace mj {

class Value;
using Array = std::vector<Value>;
using Object = std::vector<std::pair<std::string, Value>>;  // insertion-ordered

enum class Type { Null, Bool, Int, Double, String, Array, Object };

class ParseError : public std::runtime_error
{
public:
  explicit ParseError(const std::string &m) : std::runtime_error(m) {}
};

class Value
{
public:
  Value() = default;
  Value(std::nullptr_t) {}
  Value(bool b) : t_(Type::Bool), b_(b) {}
  Value(int v) : t_(Type::Int), i_(v) {}
  Value(long v) : t_(Type::Int), i_(v) {}
  Value(long long v) : t_(Type::Int), i_(v) {}
  Value(unsigned v) : t_(Type::Int), i_(static_cast<int64_t>(v)) {}
  Value(unsigned long v) : t_(Type::Int), i_(static_cast<int64_t>(v)) {}
  Value(unsigned long long v) : t_(Type::Int), i_(static_cast<int64_t>(v)) {}
  Value(double d) : t_(Type::Double), d_(d) {}
  Value(const char *s) : t_(Type::String), s_(s ? s : "") {}
  Value(std::string s) : t_(Type::String), s_(std::move(s)) {}
  Value(Array a) : t_(Type::Array), a_(std::move(a)) {}
  Value(Object o) : t_(Type::Object), o_(std::move(o)) {}

  static Value array() { return Value(Array{}); }
  static Value object() { return Value(Object{}); }

  Type type() const { return t_; }
  bool is_null() const { return t_ == Type::Null; }
  bool is_bool() const { return t_ == Type::Bool; }
  bool is_int() const { return t_ == Type::Int; }
  bool is_number() const { return t_ == Type::Int || t_ == Type::Double; }
  bool is_string() const { return t_ == Type::String; }
  bool is_array() const { return t_ == Type::Array; }
  bool is_object() const { return t_ == Type::Object; }

  bool as_bool() const { return b_; }
  int64_t as_int() const { return t_ == Type::Double ? static_cast<int64_t>(d_) : i_; }
  double as_double() const { return t_ == Type::Int ? static_cast<double>(i_) : d_; }
  const std::string &as_string() const { return s_; }
  const Array &as_array() const { return a_; }
  Array &as_array() { return a_; }
  const Object &as_object() const { return o_; }

  // Object helpers. find() returns nullptr when absent (or when not an object).
  const Value *find(const std::string &key) const;
  Value &set(const std::string &key, Value v);  // replaces existing key
  // Array helper.
  Value &push(Value v);

  std::string dump() const;
  void dump_to(std::string &out) const;

private:
  Type t_ = Type::Null;
  bool b_ = false;
  int64_t i_ = 0;
  double d_ = 0;
  std::string s_;
  Array a_;
  Object o_;
};

// Parses exactly one JSON value (surrounding whitespace allowed).
// Throws ParseError on malformed input or when nesting exceeds max_depth.
Value parse(const std::string &text, int max_depth = 64);

// Appends `s` as a JSON string literal (with quotes), sanitising invalid UTF-8.
void append_quoted(std::string &out, const std::string &s);

}  // namespace mj
