// Win32 helpers for the idamcp bridge. No IDA SDK headers here.
#pragma once

#include <cstdint>
#include <string>

namespace idamcp::platform {

// Cryptographically random bytes (BCryptGenRandom), hex-encoded. Empty on failure.
std::string random_hex(size_t nbytes);

// %LOCALAPPDATA%\idamcp (created if missing). Empty on failure.
std::string state_dir();

// Creates a directory and its parents. Returns true if it exists afterwards.
bool make_dirs(const std::string &utf8_path);

// Writes `content` to a temp file then atomically replaces `utf8_path`.
bool write_file_atomic(const std::string &utf8_path, const std::string &content);

bool remove_file(const std::string &utf8_path);

// Appends one line to a file (opened/closed per call; serialised by the caller).
bool append_line(const std::string &utf8_path, const std::string &line);

uint32_t current_pid();

// UTC timestamp, ISO 8601 with milliseconds: 2026-11-13T10:20:30.123Z
std::string utc_now_iso8601();

// Constant-time string comparison (for the auth token).
bool constant_time_equals(const std::string &a, const std::string &b);

}  // namespace idamcp::platform
