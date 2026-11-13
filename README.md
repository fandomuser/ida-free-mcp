# idamcp — MCP server for IDA Free 9.5

Lets Claude Code (or any MCP client) inspect the database you have open in
**IDA Free 9.5** on Windows: functions, disassembly, strings, imports/exports,
cross-references, call graph, basic blocks/CFG, byte search, names, comments,
renames, comments and function creation, plus Hex-Rays pseudocode wherever IDA
allows plugins to use a decompiler (see [Decompiler](#decompiler)).

It does not use IDA Pro, IDAPython, idalib, or any license workaround. Nothing in IDA is patched.

> **Disclaimer:** idamcp is an independent project. It is not affiliated with, endorsed by, or
> supported by Hex-Rays SA. IDA, IDA Free, IDA Pro and Hex-Rays are trademarks of Hex-Rays SA. Use
> of IDA is governed by its own license; idamcp only uses the public IDA SDK.

```
Claude Code ──stdio/MCP──> idamcp-server (Python, official `mcp` SDK)
                                │  newline-delimited JSON, token auth
                                ▼  127.0.0.1:<ephemeral port>
                       idamcp.dll (native IDA plugin, official IDA SDK 9.5)
                                │  execute_sync(MFF_READ / MFF_WRITE)
                                ▼
                       IDA's main thread → database you have open
```

## Why this design (verified on IDA Free 9.5)

| Option | Result on IDA Free 9.5 | Evidence |
|---|---|---|
| Hex-Rays' own "IDA MCP" | Not available | Its docs (bundled in `docs/core/mcp`) list IDA Home/Pro/Classroom and require idalib |
| IDAPython / idalib | Not available | Not shipped with Free |
| `-S` IDC script / `-A` batch mode | Rejected | IDA prints `Unknown switch '-S'` and `This version of IDA does not support the batch mode` |
| **Native C++ plugin (official SDK)** | **Works** | A probe plugin built from the official `HexRaysSA/ida-sdk` tag `v9.5.0-release` is loaded and initialised (`kernel=9.5`) |

The plugin is a normal `PLUGIN_MULTI` module. IDA creates one bridge per open
database and destroys it when the database closes.

## Requirements

- Windows 10/11 x64, IDA Free 9.5
- Visual Studio 2022+ with the C++ x64 toolset (includes CMake and Ninja), to build the plugin
- [uv](https://docs.astral.sh/uv/) (Python 3.11+ is fetched automatically)
- Claude Code CLI (`claude`)
- The official IDA SDK (MIT licensed), cloned into `third_party/`:
  ```bash
  git clone --depth 1 --branch v9.5.0-release https://github.com/HexRaysSA/ida-sdk third_party/ida-sdk
  ```

## Download

Prebuilt `idamcp.dll` builds are attached to the repository's GitHub **Releases**, together with a
`SHA256SUMS.txt`. Each one is built by GitHub Actions from the tagged commit, and the unit tests run first.
Copy the DLL to `%APPDATA%\Hex-Rays\IDA Pro\plugins\`, then set up the MCP server as described below.
To publish a new release, push a tag: `git tag v1.0.1 && git push origin v1.0.1`.

## Install

If IDA is running, the installer moves the locked old DLL aside (to `%LOCALAPPDATA%\idamcp\old`)
and installs the new one. Restart IDA afterwards to load it.

```bash
powershell -ExecutionPolicy Bypass -File scripts/install.ps1
```

The script:
1. builds `idamcp.dll` (Release, x64) and runs the C++ unit tests;
2. copies it to `%APPDATA%\Hex-Rays\IDA Pro\plugins\` (IDA's per-user plugin folder, so the IDA installation is not modified);
3. creates the server environment with locked dependencies (`uv sync --frozen`);
4. registers the server: `claude mcp add --scope user idamcp -- uv --directory <repo>\server run --frozen idamcp-server`.

Check it: `claude mcp get idamcp` should report `✔ Connected`. All 28 tools are registered;
there is no separate write option.

## Turning MCP on and off (per IDA window)

MCP is **OFF** whenever a database is opened. Nothing listens, and no client can see or reach the
database. In IDA, choose **Edit > Plugins > idamcp** to toggle it:

```
[idamcp] MCP DISABLED (turn on via Edit > Plugins > idamcp)     <- when the database loads
[idamcp] MCP ENABLED — read/write available                      <- after Edit > Plugins > idamcp
[idamcp] MCP DISABLED                                             <- after choosing it again
```

- **ON:** the bridge starts on `127.0.0.1` with a fresh random token, and every tool is available
  at once: reading and analysis, renames, comments, function creation.
- **OFF:** the listener stops, connected clients are disconnected, pending requests are cancelled
  (never executed), threads are joined, sockets are released, and the discovery file is deleted. The
  database stays open and is not modified. Turning it ON again starts a new bridge with a new token,
  and MCP clients reconnect automatically.
- Each IDA window has its own switch: `a.exe` can be ON while `b.exe` is OFF. MCP servers only
  see and talk to windows that are ON. Closing a database or IDA with MCP ON shuts the bridge
  down cleanly too.

Uninstall: `scripts/install.ps1 -Uninstall`.

## Usage

Open a binary in IDA Free, turn MCP on (Edit > Plugins > idamcp), and wait for auto-analysis to
finish. Then ask Claude Code, for example:
"Which functions reference the string 'password'? Show me the disassembly of the first one."

| Tool | Purpose |
|---|---|
| `ida_status`, `ida_select_instance` | Every database with MCP ON (name, pid, analysis state); set the default one |
| `ida_get_metadata` | File, hashes, format, CPU, bitness, image base, entry point, counts |
| `ida_list_segments` | Segments with permissions and bitness |
| `ida_list_functions`, `ida_get_function` | Functions (paginated/filterable); details, chunks, comments |
| `ida_get_disassembly` | Function or linear listing (resumable with `start_from`) |
| `ida_get_bytes` | Up to 64 KiB of raw bytes, with unloaded ranges flagged |
| `ida_get_strings`, `ida_search_strings` | IDA's string list; search by contains/exact/prefix/suffix |
| `ida_get_imports`, `ida_get_exports`, `ida_get_entrypoints` | Import slots by module; exports; program entry |
| `ida_get_xrefs_to`, `ida_get_xrefs_from` | Code/data references, including the containing function |
| `ida_get_callers`, `ida_get_callees` | Call graph: direct calls, tail jumps, indirect calls via import slots |
| `ida_get_basic_blocks`, `ida_get_control_flow_graph` | Blocks, edges and block types, optionally with instructions |
| `ida_search_bytes` | Hex patterns with `??` wildcards, or `"quoted text"` |
| `ida_get_names`, `ida_get_comments` | Names list (with demangled form); comments in a range |
| `ida_rename_function`, `ida_rename_symbol` | Rename a function, or any address (empty name removes it) |
| `ida_set_comment`, `ida_set_function_comment` | Set or remove (empty text) regular/repeatable comments |
| `ida_create_function` | Create a function at undiscovered code |
| `ida_decompile` | Hex-Rays pseudocode of a function, where IDA permits it (see [Decompiler](#decompiler)) |

Addresses are hex strings (`0x140001000`, or `140001000h`). Most tools also accept a
symbol name. Lists return `next_offset` (or `next_address` / `next_start`) to continue.

### Several databases at once

IDA opens one database per window, and the plugin runs in each IDA window. Open two executables
in two IDA windows, turn MCP on in both, and the AI can work on both. Every tool accepts an optional `database`
argument: the file name (`a.exe`), IDB name, full path, or IDA process id. Example:
"compare `CheckLicense` in old.exe and new.exe".

- `ida_status` lists the databases with MCP ON and marks the default. The default is the one chosen with
  `ida_select_instance`, otherwise the most recently opened.
- Reads without `database` go to the default database.
- **Writes without `database` are refused while more than one database is open**, unless a default
  was chosen explicitly with `ida_select_instance`. A rename can never land in the wrong file.
- Each database keeps its own connection. Requests to different databases do not wait on each other.

### Database modifications

While MCP is ON, modifications are available with no extra switch. Each change is printed in IDA's Output window, goes through IDA's normal APIs, and can be undone
with Ctrl+Z. Renames that would collide with an existing name are refused. Write requests are
never retried automatically.

### Decompiler

`ida_decompile` uses IDA's official decompiler API (`init_hexrays_plugin`, `decompile_function`).

- **IDA Home, Educational and Pro:** it returns the pseudocode of the containing function, as text
  lines. With a cloud decompiler (Home/Educational), the function is sent to Hex-Rays' servers.
- **IDA Free 9.5:** the cloud decompiler works when you press F5 yourself, but Hex-Rays does not let
  plugins use it. The IDA 9.5 release notes say the cloud decompiler's API is enabled only for "IDA
  Home, IDA Educational". It was verified on this setup: the API refuses even after a successful F5.
  The tool then returns `[decompiler_unavailable]` with that explanation. idamcp deliberately does
  not work around this, for example by calling the decompiler's internals or scraping the
  Pseudocode window.
- `ida_status` shows `capabilities.decompiler`, which says whether pseudocode is available in that
  IDA window. Calls get up to 90 s, because a decompile cannot be interrupted part-way.

### Configuration

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `IDAMCP_TIMEOUT_MS` | server | 15000 | Per-call budget (1000–120000) |
| `IDAMCP_LOG_LEVEL` | server | INFO | JSON logs to stderr |
| `IDAMCP_PORT` | IDA process | ephemeral | Fixed loopback port |

## Security model

- The plugin binds only `127.0.0.1`, uses `SO_EXCLUSIVEADDRUSE`, and rejects non-loopback peers.
- Every connection must first present a random 256-bit token (`BCryptGenRandom`), compared in
  constant time. The token is in `%LOCALAPPDATA%\idamcp\instances\ida-<pid>.json`, which only your
  user can read. Unauthenticated connections are dropped after 10 s. Request lines are capped at 1 MiB,
  and at most 8 connections are accepted.
- There is no code, script, IDC or command execution of any kind. The bridge exposes only the fixed
  set of methods listed above, with strict parameter validation on both sides.
- Byte patterns are validated before IDA's parser sees them. While a request runs, IDA's `batch` flag
  is set, so no API can open a dialog and block the UI.

## Reliability

- **UI thread:** all database access runs on IDA's main thread via `execute_sync`, and socket I/O runs
  on background threads. Each request is bounded by a page limit (≤1000 items, ≤2000 lines,
  ≤64 KiB) and a deadline. Long scans return partial results with `truncated_by_deadline: true`
  and a cursor.
- **Timeouts/cancellation:** a request is never started after its deadline, so a write cannot apply
  after the client has given up. When the client times out, it drops the connection so a late reply is
  never matched to a later request. When the MCP client cancels a call, the in-flight request is abandoned in the same way.
- **Shutdown:** turning MCP off, closing the database, or closing IDA all stop the bridge the same way:
  the request gate closes, the discovery file is removed, the listener and client sockets are closed,
  pending main-thread requests are cancelled (`set_execute_sync_availability(esa_unavailable)`), every
  thread is joined, and Winsock is released. Discovery files left behind by crashed IDA processes are
  removed automatically.
- **Logs:** the plugin writes structured JSON lines to `%LOCALAPPDATA%\idamcp\logs\bridge-<pid>.log`
  (method, duration, error code; no request contents). The server logs JSON to stderr.

## Limitations

- **No pseudocode on IDA Free** (see [Decompiler](#decompiler)).
- IDA Free has no batch mode, so a person (or the test script) must open the database in the GUI and
  turn MCP on.
- Results reflect IDA's analysis. For example, `main` is not auto-named in binaries without matching
  FLIRT signatures, and `static` functions without a PDB appear as `sub_XXXX`.
- The string list is IDA's own list, built with its current settings (Strings window → Setup).
- If a modal dialog is open in IDA, requests wait. If the dialog stays open past the deadline they
  fail with `timeout`, and nothing is executed late.
- Windows x64 only (the plugin uses Winsock/BCrypt; IDA Free's plugin API is the same elsewhere).

## Development and tests

```bash
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 -Test
```
Builds the plugin and runs the C++ unit tests (JSON parser/serializer, transport, auth timeout, limits, shutdown).

```bash
cd server && uv run pytest -m "not live"
```
Runs the Python unit tests (tool schemas, validation, error mapping, database routing and write targeting,
discovery, auth, timeouts, token rotation).

```bash
powershell -ExecutionPolicy Bypass -File scripts/run_live_tests.ps1
```
Runs the full end-to-end suite against a real IDA Free 9.5 GUI instance using the fixture
`tests/fixtures/sample.c`, which is built with `tests/fixtures/build_fixture.ps1`. The script opens IDA,
accepts the load dialog through UI Automation scoped to that IDA process, checks that MCP is OFF
after loading, and turns it on through the real Edit > Plugins > idamcp menu. It then waits for
analysis and runs `pytest -m live`. That covers reads, writes, OFF/ON shutdown checks, 5 repeated
cycles with token rotation and reconnection, and independent per-window state. Finally it closes IDA
with MCP still ON and fails unless the shutdown was clean. Add `-Installed` to test the installed DLL,
and `-TwoDatabases` to also open a second copy (`sample_b.exe`).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No IDA database has MCP turned on` | In IDA choose Edit > Plugins > idamcp; the Output window should say `MCP ENABLED`. If there's no `[idamcp]` line at all, check that `%APPDATA%\Hex-Rays\IDA Pro\plugins\idamcp.dll` exists. |
| No `[idamcp]` line in Output | The plugin did not load. Rebuild against the SDK tag matching your IDA version (`v9.5.0-release`). Make sure no `IDAUSR` override hides your user directory. |
| `timeout` errors | A modal dialog is open in IDA, or auto-analysis is busy. Close the dialog and retry. You can raise `IDAMCP_TIMEOUT_MS`. |
| A database is missing from `ida_status` | MCP is OFF in that window; turn it on there. |
| `disabled` / `cancelled` errors | MCP was turned off (or the database closed) during the call. Turn it on again; clients reconnect by themselves. |
| Tools missing in Claude | Restart Claude Code after installing or updating. |
| Several IDA windows open | `ida_status` lists them. Pass `database` (e.g. `"a.exe"`) per call, or set a default with `ida_select_instance`. If two files share a name, use the pid. |
| `install.ps1` cannot replace the DLL | Close all IDA windows and retry. |
| Bridge errors | `%LOCALAPPDATA%\idamcp\logs\bridge-<pid>.log` |

## Layout

```
plugin/      native IDA plugin (C++17, CMake, official IDA SDK 9.5)
  src/       plugin.cpp (entry/auth/dispatch), handlers.cpp (IDA API), transport.cpp,
             json.cpp, platform.cpp
  tests/     standalone C++ unit tests
server/      Python MCP server (uv project, mcp==2.3.0)
scripts/     build, install, live-test runner, UI Automation helper
tests/fixtures/  deterministic test binary source
third_party/ida-sdk/  official SDK checkout (not committed)
```
