# Changelog

All notable changes to mcp-fleet-doctor are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); versioning is [SemVer](https://semver.org/).

## [0.2.0] — security audit layer

### Added

- **`mcp-fleet-doctor audit`** — the existing fleet probes plus a heuristic risk
  report: per-server risk table, fleet summary and per-level counts, alongside
  the usual verdict table. `--json` emits a `risk` section (counts, findings,
  warnings, per-server max level, baseline status).
- **Static layer** (no spawn): `RISKY_SPAWN_ARGS` (HIGH) for literal
  pipe-to-shell / `rm -rf` / `chmod 777` / `: ||` footprints in `command` and
  `args`; `SECRET_IN_PARAM` (MED) for secret-shaped config env **key names** —
  values are never read into a finding and never rendered; production-sounding
  server names (`…prod…`, `…deploy…`) are reported as *warnings* only, because
  naming is not proof.
- **Dynamic layer** (spawn-verified, over the live `tools/list` surface):
  `DESTRUCTIVE_NO_CONFIRM` (HIGH) for destructive/irreversible actions with no
  required confirm/approval argument; `PROMPT_INJECTION_HINT` (HIGH) for
  model-directed imperatives in tool descriptions; `SECRET_IN_PARAM` (CRIT) for
  secret-shaped string parameters; `EGRESS_URL_FIELD` (MED) for arbitrary
  URL/endpoint/webhook fields; `UNSPECIFIED_SCHEMA` (LOW, MED when the name is
  destructive) for payload-bearing tools that declare no `inputSchema`.
- **`--strict`** — exit 1 when any HIGH/CRIT finding is present, for CI gating.
- **Opt-in drift tracking** — `--track` stores a baseline keyed by
  `(config path, server name)`: a sha256 over the sorted canonical tool
  descriptors plus the tool names. The next tracked audit reports
  `BASELINE_DRIFT_NEW` (HIGH) for new high-risk/destructive tools and
  `BASELINE_DRIFT_REMOVED` (INFO) for tools that disappeared. Location:
  `~/.cache/mcp-fleet-doctor/baseline.json`, overridable via `MCPFD_BASELINE`
  or `--baseline-file`; missing or malformed files are treated as "no baseline
  yet". Without `--track` no state is written anywhere.
- **`examples/risky_server.py`** — a deliberately risky stdio MCP server
  (destructive tool, secret-shaped parameter, arbitrary endpoint plus a
  model-directed description) with a benign `echo` tool as the control case.
- **`examples/claude_config_with_risky.json`** — one-command demo config that
  shows the verdict table and the risk table together.
- **Tests** — 32 new tests covering every finding class, the real-spawn dynamic
  reasoning against both the healthy and the risky example servers, the
  drift lifecycle, `--strict` exit codes, and the guarantee that no environment
  value ever reaches stdout or the JSON payload. 42 tests total.

### Changed

- `ProbeResult` now carries `tool_defs` — the tool descriptors returned by
  `tools/list`. The plain (non-`audit`) `--json` payload deliberately strips it,
  so the output shape of the original command is unchanged.
- The MCP `initialize` clientInfo version is taken from `__version__` instead of
  being hard-coded.
- Version reported by `--version` and the installed entry point is now 0.2.0.

## [0.1.0] — config-level fleet diagnostics

- Reads the configs where MCP servers are actually declared: Claude Desktop,
  Cursor, VS Code, WindSurf, opencode, Hermes, or any explicit JSON/YAML file
  (`mcpServers` / `mcp_servers` / `servers` / flat map).
- Probes every configured server the way a real client does: spawn with the
  config env (`${VAR}` expanded, safe base env), `initialize` →
  `notifications/initialized` → `tools/list`, with `select()`-based deadlines so
  a hanging server can never hang the doctor.
- Six failure-class verdicts with reasons parsed from the server's own stderr:
  `OK`, `COMMAND_NOT_FOUND`, `CRASHED_ON_STARTUP` (missing module / traceback),
  `STARTED_BUT_NO_RESPONSE`, `CONNECTED_BUT_NO_TOOLS`, `PROBE_ERROR`.
- Responses matched by request id rather than read sequentially, so servers that
  emit noise on stdout do not break the probe.
- Static checks before spawning: bare interpreter names that resolve per host
  PATH, commands missing from PATH, broken interpreters, unresolved `${ENV}`
  placeholders (key names only — values are never echoed), missing
  `working_directory`.
- Disabled-server awareness: `enabled: false` / `disabled: true` servers are
  reported and skipped, never failed.
- CI/cron-friendly exit codes (`0` healthy, `1` any fault, `2` nothing to probe)
  and `--json` output.
- Zero runtime dependencies for JSON configs; PyYAML is optional and only used
  if present, with a minimal built-in YAML subset parser as fallback.
- Example server matrix (healthy / missing dependency / hanging / missing
  command) in two config formats, plus a test suite that spawns all of them.

[0.2.0]: https://github.com/brodewa369/mcp-fleet-doctor/releases/tag/v0.2.0
[0.1.0]: https://github.com/brodewa369/mcp-fleet-doctor/releases/tag/v0.1.0
