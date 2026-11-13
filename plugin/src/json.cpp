#include "json.hpp"

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace mj {

const Value *Value::find(const std::string &key) const
{
  if ( t_ != Type::Object )
    return nullptr;
  for ( const auto &kv : o_ )
    if ( kv.first == key )
      return &kv.second;
  return nullptr;
}

Value &Value::set(const std::string &key, Value v)
{
  if ( t_ != Type::Object )
  {
    *this = Value(Object{});
  }
  for ( auto &kv : o_ )
  {
    if ( kv.first == key )
    {
      kv.second = std::move(v);
      return kv.second;
    }
  }
  o_.emplace_back(key, std::move(v));
  return o_.back().second;
}

Value &Value::push(Value v)
{
  if ( t_ != Type::Array )
    *this = Value(Array{});
  a_.push_back(std::move(v));
  return a_.back();
}

//--------------------------------------------------------------------------
// Serialisation
//--------------------------------------------------------------------------
static void append_utf8(std::string &out, uint32_t cp)
{
  if ( cp < 0x80 )
  {
    out += static_cast<char>(cp);
  }
  else if ( cp < 0x800 )
  {
    out += static_cast<char>(0xC0 | (cp >> 6));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  }
  else if ( cp < 0x10000 )
  {
    out += static_cast<char>(0xE0 | (cp >> 12));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  }
  else
  {
    out += static_cast<char>(0xF0 | (cp >> 18));
    out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  }
}

// Decodes one UTF-8 sequence at s[i]. On success returns its length and sets cp;
// on invalid input returns 0.
static size_t decode_utf8(const std::string &s, size_t i, uint32_t *cp)
{
  const unsigned char c0 = static_cast<unsigned char>(s[i]);
  size_t n;
  uint32_t v;
  uint32_t minv;
  if ( c0 < 0x80 ) { *cp = c0; return 1; }
  else if ( (c0 & 0xE0) == 0xC0 ) { n = 2; v = c0 & 0x1F; minv = 0x80; }
  else if ( (c0 & 0xF0) == 0xE0 ) { n = 3; v = c0 & 0x0F; minv = 0x800; }
  else if ( (c0 & 0xF8) == 0xF0 ) { n = 4; v = c0 & 0x07; minv = 0x10000; }
  else return 0;
  if ( i + n > s.size() )
    return 0;
  for ( size_t k = 1; k < n; k++ )
  {
    const unsigned char c = static_cast<unsigned char>(s[i + k]);
    if ( (c & 0xC0) != 0x80 )
      return 0;
    v = (v << 6) | (c & 0x3F);
  }
  if ( v < minv || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF) )
    return 0;
  *cp = v;
  return n;
}

void append_quoted(std::string &out, const std::string &s)
{
  static const char hex[] = "0123456789abcdef";
  out += '"';
  size_t i = 0;
  while ( i < s.size() )
  {
    const unsigned char c = static_cast<unsigned char>(s[i]);
    if ( c < 0x80 )
    {
      switch ( c )
      {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
          if ( c < 0x20 || c == 0x7F )
          {
            out += "\\u00";
            out += hex[c >> 4];
            out += hex[c & 0xF];
          }
          else
          {
            out += static_cast<char>(c);
          }
      }
      i++;
      continue;
    }
    uint32_t cp;
    const size_t n = decode_utf8(s, i, &cp);
    if ( n == 0 )
    {
      out += "\xEF\xBF\xBD";  // U+FFFD
      i++;
    }
    else
    {
      out.append(s, i, n);
      i += n;
    }
  }
  out += '"';
}

void Value::dump_to(std::string &out) const
{
  switch ( t_ )
  {
    case Type::Null: out += "null"; break;
    case Type::Bool: out += b_ ? "true" : "false"; break;
    case Type::Int:
      {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(i_));
        out += buf;
      }
      break;
    case Type::Double:
      if ( !std::isfinite(d_) )
      {
        out += "null";
      }
      else
      {
        char buf[40];
        std::snprintf(buf, sizeof(buf), "%.17g", d_);
        out += buf;
      }
      break;
    case Type::String: append_quoted(out, s_); break;
    case Type::Array:
      out += '[';
      for ( size_t k = 0; k < a_.size(); k++ )
      {
        if ( k != 0 )
          out += ',';
        a_[k].dump_to(out);
      }
      out += ']';
      break;
    case Type::Object:
      out += '{';
      for ( size_t k = 0; k < o_.size(); k++ )
      {
        if ( k != 0 )
          out += ',';
        append_quoted(out, o_[k].first);
        out += ':';
        o_[k].second.dump_to(out);
      }
      out += '}';
      break;
  }
}

std::string Value::dump() const
{
  std::string out;
  dump_to(out);
  return out;
}

//--------------------------------------------------------------------------
// Parsing
//--------------------------------------------------------------------------
namespace {

class Parser
{
public:
  Parser(const std::string &s, int max_depth) : s_(s), max_depth_(max_depth) {}

  Value parse_document()
  {
    skip_ws();
    Value v = parse_value(0);
    skip_ws();
    if ( pos_ != s_.size() )
      fail("trailing characters after JSON value");
    return v;
  }

private:
  const std::string &s_;
  size_t pos_ = 0;
  int max_depth_;

  [[noreturn]] void fail(const char *what) const
  {
    throw ParseError(std::string(what) + " at offset " + std::to_string(pos_));
  }

  void skip_ws()
  {
    while ( pos_ < s_.size() )
    {
      const char c = s_[pos_];
      if ( c == ' ' || c == '\t' || c == '\n' || c == '\r' )
        pos_++;
      else
        break;
    }
  }

  bool consume_literal(const char *lit)
  {
    const size_t n = std::strlen(lit);
    if ( s_.compare(pos_, n, lit) == 0 )
    {
      pos_ += n;
      return true;
    }
    return false;
  }

  Value parse_value(int depth)
  {
    if ( depth > max_depth_ )
      fail("maximum nesting depth exceeded");
    if ( pos_ >= s_.size() )
      fail("unexpected end of input");
    const char c = s_[pos_];
    switch ( c )
    {
      case '{': return parse_object(depth);
      case '[': return parse_array(depth);
      case '"': return Value(parse_string());
      case 't': if ( consume_literal("true") ) return Value(true); break;
      case 'f': if ( consume_literal("false") ) return Value(false); break;
      case 'n': if ( consume_literal("null") ) return Value(); break;
      default:
        if ( c == '-' || (c >= '0' && c <= '9') )
          return parse_number();
    }
    fail("invalid JSON value");
  }

  Value parse_object(int depth)
  {
    pos_++;  // '{'
    Value obj = Value::object();
    skip_ws();
    if ( pos_ < s_.size() && s_[pos_] == '}' )
    {
      pos_++;
      return obj;
    }
    for ( ;; )
    {
      skip_ws();
      if ( pos_ >= s_.size() || s_[pos_] != '"' )
        fail("expected object key");
      std::string key = parse_string();
      skip_ws();
      if ( pos_ >= s_.size() || s_[pos_] != ':' )
        fail("expected ':'");
      pos_++;
      skip_ws();
      obj.set(key, parse_value(depth + 1));
      skip_ws();
      if ( pos_ >= s_.size() )
        fail("unexpected end of input in object");
      if ( s_[pos_] == ',' ) { pos_++; continue; }
      if ( s_[pos_] == '}' ) { pos_++; return obj; }
      fail("expected ',' or '}'");
    }
  }

  Value parse_array(int depth)
  {
    pos_++;  // '['
    Value arr = Value::array();
    skip_ws();
    if ( pos_ < s_.size() && s_[pos_] == ']' )
    {
      pos_++;
      return arr;
    }
    for ( ;; )
    {
      skip_ws();
      arr.push(parse_value(depth + 1));
      skip_ws();
      if ( pos_ >= s_.size() )
        fail("unexpected end of input in array");
      if ( s_[pos_] == ',' ) { pos_++; continue; }
      if ( s_[pos_] == ']' ) { pos_++; return arr; }
      fail("expected ',' or ']'");
    }
  }

  uint32_t parse_hex4()
  {
    if ( pos_ + 4 > s_.size() )
      fail("truncated \\u escape");
    uint32_t v = 0;
    for ( int k = 0; k < 4; k++ )
    {
      const char c = s_[pos_++];
      v <<= 4;
      if ( c >= '0' && c <= '9' ) v |= c - '0';
      else if ( c >= 'a' && c <= 'f' ) v |= c - 'a' + 10;
      else if ( c >= 'A' && c <= 'F' ) v |= c - 'A' + 10;
      else fail("invalid hex digit in \\u escape");
    }
    return v;
  }

  std::string parse_string()
  {
    pos_++;  // opening quote
    std::string out;
    for ( ;; )
    {
      if ( pos_ >= s_.size() )
        fail("unterminated string");
      const unsigned char c = static_cast<unsigned char>(s_[pos_]);
      if ( c == '"' )
      {
        pos_++;
        return out;
      }
      if ( c < 0x20 )
        fail("control character in string");
      if ( c != '\\' )
      {
        out += static_cast<char>(c);
        pos_++;
        continue;
      }
      pos_++;
      if ( pos_ >= s_.size() )
        fail("unterminated escape");
      const char e = s_[pos_++];
      switch ( e )
      {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u':
          {
            uint32_t cp = parse_hex4();
            if ( cp >= 0xD800 && cp <= 0xDBFF )
            {
              if ( pos_ + 2 <= s_.size() && s_[pos_] == '\\' && s_[pos_ + 1] == 'u' )
              {
                pos_ += 2;
                const uint32_t lo = parse_hex4();
                if ( lo < 0xDC00 || lo > 0xDFFF )
                  fail("invalid low surrogate");
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
              }
              else
              {
                fail("unpaired high surrogate");
              }
            }
            else if ( cp >= 0xDC00 && cp <= 0xDFFF )
            {
              fail("unpaired low surrogate");
            }
            append_utf8(out, cp);
          }
          break;
        default:
          fail("invalid escape character");
      }
    }
  }

  Value parse_number()
  {
    const size_t start = pos_;
    bool is_float = false;
    if ( s_[pos_] == '-' )
      pos_++;
    if ( pos_ >= s_.size() )
      fail("truncated number");
    if ( s_[pos_] == '0' )
    {
      pos_++;
    }
    else if ( s_[pos_] >= '1' && s_[pos_] <= '9' )
    {
      while ( pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9' )
        pos_++;
    }
    else
    {
      fail("invalid number");
    }
    if ( pos_ < s_.size() && s_[pos_] == '.' )
    {
      is_float = true;
      pos_++;
      if ( pos_ >= s_.size() || s_[pos_] < '0' || s_[pos_] > '9' )
        fail("invalid fraction");
      while ( pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9' )
        pos_++;
    }
    if ( pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E') )
    {
      is_float = true;
      pos_++;
      if ( pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-') )
        pos_++;
      if ( pos_ >= s_.size() || s_[pos_] < '0' || s_[pos_] > '9' )
        fail("invalid exponent");
      while ( pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9' )
        pos_++;
    }
    const std::string tok = s_.substr(start, pos_ - start);
    if ( !is_float )
    {
      errno = 0;
      char *end = nullptr;
      const long long v = std::strtoll(tok.c_str(), &end, 10);
      if ( errno == 0 && end != nullptr && *end == '\0' )
        return Value(v);
      // Out of int64 range: fall through to double.
    }
    char *end = nullptr;
    const double d = std::strtod(tok.c_str(), &end);
    return Value(d);
  }
};

}  // namespace

Value parse(const std::string &text, int max_depth)
{
  Parser p(text, max_depth);
  return p.parse_document();
}

}  // namespace mj
