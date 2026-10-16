<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen" />
  <img src="https://img.shields.io/badge/MCP-diagnostics-purple" />
</p>

# MCP Fleet Doctor

**Config-level MCP server doctor — probes every server in your client configs the way a real client would, and says exactly what is broken and why.**

```text
$ mcp-fleet-doctor --client hermes
== mcp-fleet-doctor | client=hermes | ~/.hermes/config.yaml
✅ context7        OK                     2 tools: query-docs, resolve-library-id
✅ filesystem      OK                     14 tools: create_directory, directory_tree, edit_file, … (+8 more)
✅ semantic-vault  OK                     11 tools: get_chunk, index_stats, read_vault_file, … (+5 more)
❌ broken-server   CRASHED_ON_STARTUP     missing module 'pyyaml' in that interpreter — pin the python + install it
🟡 runaway-server  STARTED_BUT_NO_RESPONSE  alive but no response to initialize (hang/daemon class)
== 3/5 OK
$ echo $?
1
```

## The problem it was built for

A friend's production agent went three days without its semantic-vault search.
The chat UI looked completely normal. The MCP client had silently **parked**
one server: it failed its startup handshake three times on connection attempt —
because the config said bare `command: python3`, which resolved to a different
interpreter than intended, which lacked a dependency, which crashed on import.

Nobody noticed until a tool was needed. The failure lived only in client logs.

**Every existing MCP diagnostic answers a different question.** Inspectors,
jam-testers, analyzer-style `mcp-doctor`s all want you to hand over a *single*
already-known server (a URL, an npx command). None of them read the configs
where servers are actually declared, none audit the whole fleet, and none
distinguish **"process died on startup"** from **"process alive but not MCP"**
from **"connected but lists zero tools"** — the exact failure classes that
clients respond to with silent parking or invisible degradation.

MCP Fleet Doctor starts from *your configs* and gives a verdict per server.

## Features

- **Config-first** — reads Claude Desktop / Cursor / VS Code / WindSurf / opencode / Hermes configs, or any explicit JSON/YAML file. No hand-copying commands.
- **Real handshake** — spawns each server and performs `initialize` → `notifications/initialized` → `tools/list`; verifies the server actually speaks MCP.
- **Failure-class verdicts** — six distinct verdicts (see below) with reasons parsed from the server's own stderr (`ModuleNotFoundError…` becomes "missing module X in that interpreter", not a hexdump of pain).
- **Static checks before spawning** — bare interpreter names (`python3` resolving per host PATH), commands missing from PATH, unresolved `${ENV}` placeholders (names only — values are never echoed), missing `working_directory`.
- **Disabled-aware** — servers switched off in config are reported but not failed; the doctor's exit code reflects *your* active fleet.
- **Zero dependencies** — pure stdlib for JSON configs (PyYAML optional, used only if you have YAML configs and happen to have it installed).
- **CI/cron-friendly** — exit code `0` all healthy, `1` any fault, `2` nothing to probe; `--json` for dashboards.

## Verdicts

| Verdict | Meaning | Typical cause |
|---|---|---|
| ✅ `OK` | Handshake + tools listing works | — |
| 🚫 `COMMAND_NOT_FOUND` | Can't spawn | binary missing from the client's PATH; bare name never installed here |
| ❌ `CRASHED_ON_STARTUP` | Exited during handshake, reason parsed from stderr | missing deps, wiped venv after an interpreter upgrade, import error |
| 🟡 `STARTED_BUT_NO_RESPONSE` | Process alive, ignored MCP | non-MCP daemon, malformed stdio loop, deadlock |
| 🫥 `CONNECTED_BUT_NO_TOOLS` | Handshake ok, 0 tools listed | capability negotiation bug |
| 💥 `PROBE_ERROR` | The doctor itself hiccupped | report it |

## Usage

```bash
# Auto-detect which client config exists (probes the one with declared servers)
mcp-fleet-doctor

# Audit one client explicitly
mcp-fleet-doctor --client claude
mcp-fleet-doctor --client cursor

# Audit an arbitrary file (any client, JSON or YAML, regardless of where it came from)
mcp-fleet-doctor --config ./my_agent/config.yaml

# One server only
mcp-fleet-doctor --client hermes -s semantic-vault

# Machine-readable, for cron / CI dashboards
mcp-fleet-doctor --config mcp.json --json | jq '.summary'
```

Slow npm/npx servers may need more patience:

```bash
mcp-fleet-doctor --client claude --startup-timeout 15 --handshake-timeout 25 --call-timeout 40
```

## Install

```bash
pip install mcp-fleet-doctor     # → installs the `mcp-fleet-doctor` command
# or run straight from source:
python -m mcp_fleet_doctor.cli --config path/to/config
```

On Arch/CachyOS-style systems with an external-managed python (PEP 668), pip
refuses to install into it — use pipx or a venv:

```bash
pipx install mcp-fleet-doctor
# or
python -m venv .venv && .venv/bin/pip install -e .
```

Nothing is ever modified: read-only config parsing, and spawned servers get
terminated after the probe.

## How a probe works

```mermaid
flowchart TD
    A[Load config: client defaults or --config] --> B[Static checks: interpreter, PATH, env placeholders, cwd]
    B --> C{stdio server declared?}
    C -->|no| Z[report + skip]
    C -->|yes|    D[spawn with safe base env + client env, env placeholders expanded]
    D --> E[initialize request]
    E --> F{responds?}
    F -->|died| G[CRASHED_ON_STARTUP — stderr parsed for missing module / traceback]
    F -->|silent| H[STARTED_BUT_NO_RESPONSE — hang/daemon class]
    F -->|ok| I[notifications/initialized — sent, never awaited]
    I --> J[tools/list]
    J -->|0 tools| K[CONNECTED_BUT_NO_TOOLS]
    J -->|n tools| L[OK — n tools]
```

Production lessons baked into the protocol layer:

- Responses are matched **by request id**, not read sequentially — real servers
  emit noise (unknown-method errors, log lines) at the worst moments.
- The `notifications/initialized` step is sent but never awaited; some servers
  reject it (that's fine) and blocking on it stalls honest probes.
- stdout is read via `select()` with deadlines — a hanging server times the
  probe out instead of hanging the doctor.
- stdout EOF is distinguished from timeout; a server that died after barely
  starting gets a crash verdict with a parsed reason, not a silent timeout.

## Config support

| Client | Default path | Format | Key |
|---|---|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` / `~/.claude/claude_desktop_config.json` | JSON | `mcpServers` |
| Cursor | `~/.cursor/mcp.json` | JSON | `mcpServers` |
| VS Code | `~/.config/Code/User/mcp.json` | JSON | `servers` |
| WindSurf | `~/.codeium/windsurf/mcp_config.json` | JSON | `mcpServers` |
| OpenCode | `~/.config/opencode/opencode.json` | JSON | `mcpServers` |
| Hermes Agent | `~/.hermes/config.yaml` | YAML | `mcp_servers` |
| any file | `--config path` | JSON or YAML | `mcpServers` / `mcp_servers` / `servers` / flat |

YAML configs: parsed with PyYAML when available; otherwise a minimal built-in
indentation parser handles the regular config subset (maps, lists, scalars).
Exotic YAML beyond client configs is out of scope by design — JSON clients need
nothing installed.

Remote/HTTP servers (`"url": …` entries) are out of scope in v1 — the doctor
focuses on the stdio failure surface where silent parking happens.

## Testing

The test matrix spawns the actual example servers — healthy, crash-on-import,
hanging, and missing-command — so every verdict class is exercised for real:

```bash
python -m unittest discover -s tests -t .
```

`examples/` contains the matrix as runnable servers plus config files in both
formats; point `--config` at them to see all verdicts in one run.

## Troubleshooting cookbook

The doctor's own output maps 1:1 to these fixes:

| Verdict / hint | What it means | What to do |
|---|---|---|
| `bare interpreter 'python3'` | The config trusts host PATH to pick the interpreter | Edit the client config: `command: /absolute/path/to/venv/bin/python` |
| `command 'x' not found on PATH` | The binary is not installed where the *client* resolves PATH | Install it (npm/pip/uv), or pin the absolute path |
| `missing module 'X' in that interpreter` | The server crashed importing a dependency | Install `X` **into that exact interpreter** — `path/to/python -m pip install X` |
| `env $VAR referenced but not set` | Config placeholder has no value in this shell | Export it where the client launches, or hard-code a safe non-secret value |
| `STARTED_BUT_NO_RESPONSE` | Process lives but ignores MCP | Run it by hand; check whether it's actually a stdio MCP server |
| `CONNECTED_BUT_NO_TOOLS` | Handshake ok, 0 tools | Check the server's capability declarations / version compat with your client |
| disabled servers `skipped` | Config deliberately off | Nothing to fix unless you *meant* to enable it |

## Roadmap

- v0.2: HTTP/SSE verdicts; `--fix` hints (e.g. "pip install X into venv python Y" extracted live from the crash)
- v0.3: `watch` mode; a cron recipe in the README; Prometheus-ready `--json` schema versioning

## License

MIT — see [LICENSE](LICENSE).
