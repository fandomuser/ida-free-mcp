#include "platform.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#include <shlobj.h>

#include <cstdio>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace idamcp::platform {

static std::wstring widen(const std::string &s)
{
  if ( s.empty() )
    return std::wstring();
  const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring w(static_cast<size_t>(n), L'\0');
  ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), &w[0], n);
  return w;
}

static std::string narrow(const std::wstring &w)
{
  if ( w.empty() )
    return std::string();
  const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
  std::string s(static_cast<size_t>(n), '\0');
  ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), &s[0], n, nullptr, nullptr);
  return s;
}

std::string random_hex(size_t nbytes)
{
  std::vector<unsigned char> buf(nbytes);
  if ( !BCRYPT_SUCCESS(::BCryptGenRandom(nullptr, buf.data(), static_cast<ULONG>(buf.size()),
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG)) )
    return std::string();
  static const char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(nbytes * 2);
  for ( unsigned char c : buf )
  {
    out += hex[c >> 4];
    out += hex[c & 0xF];
  }
  return out;
}

bool make_dirs(const std::string &utf8_path)
{
  const std::wstring w = widen(utf8_path);
  const int rc = ::SHCreateDirectoryExW(nullptr, w.c_str(), nullptr);
  if ( rc == ERROR_SUCCESS || rc == ERROR_ALREADY_EXISTS || rc == ERROR_FILE_EXISTS )
    return true;
  const DWORD attrs = ::GetFileAttributesW(w.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

std::string state_dir()
{
  PWSTR p = nullptr;
  std::string base;
  if ( SUCCEEDED(::SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &p)) )
    base = narrow(p);
  if ( p != nullptr )
    ::CoTaskMemFree(p);
  if ( base.empty() )
    return std::string();
  const std::string dir = base + "\\idamcp";
  return make_dirs(dir) ? dir : std::string();
}

bool write_file_atomic(const std::string &utf8_path, const std::string &content)
{
  const std::wstring dst = widen(utf8_path);
  const std::wstring tmp = dst + L".tmp";
  HANDLE h = ::CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if ( h == INVALID_HANDLE_VALUE )
    return false;
  DWORD written = 0;
  const BOOL ok = ::WriteFile(h, content.data(), static_cast<DWORD>(content.size()), &written, nullptr);
  ::FlushFileBuffers(h);
  ::CloseHandle(h);
  if ( !ok || written != content.size() )
  {
    ::DeleteFileW(tmp.c_str());
    return false;
  }
  if ( !::MoveFileExW(tmp.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) )
  {
    ::DeleteFileW(tmp.c_str());
    return false;
  }
  return true;
}

bool remove_file(const std::string &utf8_path)
{
  return ::DeleteFileW(widen(utf8_path).c_str()) != 0;
}

bool append_line(const std::string &utf8_path, const std::string &line)
{
  HANDLE h = ::CreateFileW(widen(utf8_path).c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if ( h == INVALID_HANDLE_VALUE )
    return false;
  std::string data = line;
  data += "\r\n";
  DWORD written = 0;
  const BOOL ok = ::WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
  ::CloseHandle(h);
  return ok && written == data.size();
}

uint32_t current_pid()
{
  return static_cast<uint32_t>(::GetCurrentProcessId());
}

std::string utc_now_iso8601()
{
  SYSTEMTIME st;
  ::GetSystemTime(&st);
  char buf[40];
  std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
  return buf;
}

bool constant_time_equals(const std::string &a, const std::string &b)
{
  if ( a.size() != b.size() )
    return false;
  unsigned char diff = 0;
  for ( size_t i = 0; i < a.size(); i++ )
    diff |= static_cast<unsigned char>(a[i] ^ b[i]);
  return diff == 0;
}

}  // namespace idamcp::platform
