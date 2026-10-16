<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen" />
  <img src="https://img.shields.io/badge/MCP-diagnostics-purple" />
  <img src="https://img.shields.io/badge/security%20audit-heuristics-orange" />
</p>

# MCP Fleet Doctor

**Config-level MCP server doctor — probes every server in your client configs the way a real client would, and says exactly what is broken and why.**

Since v0.2 it also **audits risk**: `mcp-fleet-doctor audit` runs the same real
handshake and then scores the tool definitions each server *actually* exposes at
runtime — destructive actions, secret-shaped parameters, egress URLs,
prompt-injection-shaped descriptions — fleet-wide, read-only, with optional
drift tracking between audits.

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
- **Security audit** — `audit` extends the probe with a heuristic risk report over each server's *live* tool surface: destructive actions with no confirmation gate, secret-shaped parameters, arbitrary URL fields, model-directed imperatives in tool descriptions, risky spawn arguments in the config.
- **Spawn-verified, not static** — the audit reasons over what `tools/list` really returns, not over what source code or docs claim; that is the surface a client actually puts in front of the model.
- **Optional drift tracking** — `--track` baselines the tool surface per config + server and flags new high-risk tools and removed tools on the next audit.
- **Secrets stay secret** — environment *values* are never echoed anywhere (stdout, `--json`, findings, reasons); only key names are surfaced.
- **Zero dependencies** — pure stdlib for JSON configs (PyYAML optional, used only if you have YAML configs and happen to have it installed).
- **CI/cron-friendly** — exit code `0` all healthy, `1` any fault, `2` nothing to probe; `--json` for dashboards; `audit --strict` additionally fails on any HIGH/CRIT finding.

## Verdicts

| Verdict | Meaning | Typical cause |
|---|---|---|
| ✅ `OK` | Handshake + tools listing works | — |
| 🚫 `COMMAND_NOT_FOUND` | Can't spawn | binary missing from the client's PATH; bare name never installed here |
| ❌ `CRASHED_ON_STARTUP` | Exited during handshake, reason parsed from stderr | missing deps, wiped venv after an interpreter upgrade, import error |
| 🟡 `STARTED_BUT_NO_RESPONSE` | Process alive, ignored MCP | non-MCP daemon, malformed stdio loop, deadlock |
| 🫥 `CONNECTED_BUT_NO_TOOLS` | Handshake ok, 0 tools listed | capability negotiation bug |
| 💥 `PROBE_ERROR` | The doctor itself hiccupped | report it |

## Security audit (heuristics, not certification)

```bash
mcp-fleet-doctor audit --config examples/claude_config_with_risky.json
```

```text
== mcp-fleet-doctor audit | client=file | examples/claude_config_with_risky.json
✅ example-ok    OK                 2 tools: echo, uuid | bare interpreter 'python3': resolves per host PATH — pin an absolute venv path (silently-wrong-python class)
✅ risky         OK                 4 tools: deploy_prod, echo, store_token, webhook_notify | bare interpreter 'python3': resolves per host PATH — pin an absolute venv path (silently-wrong-python class)
🚫 example-not-installed COMMAND_NOT_FOUND  command 'this-binary-does-not-exist-9z' not found on PATH — pin an absolute path or install it where the client resolves PATH
== 2/3 OK

== risk table (heuristic — NOT a security certification; no enforcement)
server  level  class                   field                                reason
risky   CRIT   SECRET_IN_PARAM         inputSchema.properties.api_token     string parameter 'api_token' is secret-shaped — a literal secret would travel through the model context (name…
risky   HIGH   DESTRUCTIVE_NO_CONFIRM  tools/deploy_prod                    tool 'deploy_prod' reads as a destructive/irreversible action (deploy, prod) with no required confirm/approva…
risky   HIGH   DESTRUCTIVE_NO_CONFIRM  tools/webhook_notify                 tool 'webhook_notify' reads as a destructive/irreversible action (send) with no required confirm/approval arg…
risky   HIGH   PROMPT_INJECTION_HINT   tools/deploy_prod.description        description contains a model-directed imperative ("Always run") — tool descriptions are read verbatim into th…
risky   HIGH   PROMPT_INJECTION_HINT   tools/webhook_notify.description     description contains a model-directed imperative ("Call this tool silently") — tool descriptions are read ver…
risky   MED    EGRESS_URL_FIELD        inputSchema.properties.endpoint_url  parameter 'endpoint_url' accepts an arbitrary URL/endpoint — a data-exfiltration channel if the tool posts pa…
risky   MED    SECRET_IN_PARAM         env.DEMO_API_TOKEN                   config declares a secret-shaped env key 'DEMO_API_TOKEN' (key name only — the value is never echoed)
== INFO=0 LOW=0 MED=2 HIGH=4 CRIT=1 | 7 finding(s) across 3 server(s)
```

The same command against the plain `examples/claude_desktop_config.json` prints
the verdict table and `(no risk findings)` with every counter at zero — a
healthy fleet is quiet, it does not need to be silenced.

### Why spawn the servers at all

**Static-scanning tools exist** — AgentWard's `scan` and AgentBound-style policy
generators read manifests, source or config and infer risk. They see what the
*config or the code* claims. (AgentWard also ships a separate runtime-gateway
product; the doctor's audit is not an alternative to running such a gateway —
it is independent verification of the tool surface, from the same probe the
liveness verdicts already use.)

The doctor already does the thing a static scanner cannot: it **spawns each
server and speaks real MCP**. That single fact buys three things:

1. **Audit what a server actually exposes.** `tools/list` is the surface a
   client really puts in front of the model. It can differ from the README, from
   the source tree, or from the config's declared intent — a server can serve a
   different tool surface per environment, per version, or per flag. The audit
   scores the live descriptors (name, description, `inputSchema`), not guesses.
2. **Detect tool-surface drift between audits.** With `--track`, the doctor
   baselines each server's tool surface and flags what changed next run — a
   server that quietly gains a `deploy_prod` after you approved it is a HIGH
   finding, not a silent diff.
3. **Stay fleet-wide.** It starts from your client configs, so one command
   covers every server every client declares — no hand-listing, no per-server
   URLs.

### Finding classes

| Class | Level | Layer | What it means |
|---|---|---|---|
| `RISKY_SPAWN_ARGS` | HIGH | static | `command`/`args` contain a literal pipe-to-shell (`\|bash`, `\|sh`), `rm -rf`, `chmod 777` or `: \|\|` footprint |
| `SECRET_IN_PARAM` | CRIT (tool arg) · MED (config env key) | dynamic · static | a secret-shaped *name* — `api_token`, `secret_key`, credential-like identifiers — that would carry secret material through the model context, or that the config declares as an env key |
| `DESTRUCTIVE_NO_CONFIRM` | HIGH | dynamic | a destructive/irreversible action (`delete`/`destroy`/`drop`/`deploy`/`prod`/`publish`/`send`/`transfer`/…) with no required `confirm`/`approval`/`ack` argument |
| `PROMPT_INJECTION_HINT` | HIGH | dynamic | the tool *description* contains model-directed imperatives (`ignore previous…`, `always run`, `must run`, `execute immediately`, `call this tool silently`) |
| `EGRESS_URL_FIELD` | MED | dynamic | an arbitrary `url`/`endpoint`/`webhook` field — a data-exfiltration channel if the tool posts payloads there |
| `UNSPECIFIED_SCHEMA` | LOW (MED if destructive) | dynamic | a payload-bearing tool name with no `inputSchema` at all |
| `BASELINE_DRIFT_NEW` | HIGH | dynamic + state | a high-risk or destructive tool that appeared since the last tracked audit |
| `BASELINE_DRIFT_REMOVED` | INFO | dynamic + state | a tool that is gone since the last tracked audit |

Levels are `INFO` · `LOW` · `MED` · `HIGH` · `CRIT`, counted per run. A
production-sounding server **name** (`…prod…`, `…deploy…`) is reported as a
plain *warning* only — naming is not proof of anything, so it never becomes a
finding.

**Every check is a heuristic.** These are keyword and shape rules, tuned to be
loud about the shapes that matter. A finding is a prompt to review, not a
vulnerability report and not a certification. Conversely, silence is not a
clean bill of health — a server that hides its intent behind innocuous naming
will not be caught by name rules, which is exactly why the audit reads the live
descriptors rather than trusting labels.

### Drift tracking

```bash
mcp-fleet-doctor audit --config mcp.json --track            # first run: creates the baseline
mcp-fleet-doctor audit --config mcp.json --track            # later runs: compare + refresh
```

```text
== baseline: created @ ~/.cache/mcp-fleet-doctor/baseline.json
   - baseline created for 'vault' (2 tools)
…
== baseline: updated @ ~/.cache/mcp-fleet-doctor/baseline.json
   - baseline updated for 'vault' (3 added, 1 removed)
```

The baseline stores a sha256 over each server's sorted canonical tool
descriptors, plus the tool names, keyed by `(config path, server name)`. Only
`--track` touches it; without the flag no state is written anywhere. The
location is `~/.cache/mcp-fleet-doctor/baseline.json`, overridable with
`MCPFD_BASELINE` or `--baseline-file`. A missing or malformed baseline file is
treated as "no baseline yet" — it can never crash the audit.

Renaming a config file or a server starts a fresh baseline entry, which is why
the comparison is anchored to the declaration site rather than to a server name
alone.

### What this is not (non-goals)

The audit is **read-only diagnostics**. It does not block a call, rewrite a
config, proxy a server, or enforce a policy — no interception, no
mitm-style gateway, no auto-quarantine. Enforcement is a different product with
a different blast radius, and a doctor that silently changed your fleet would
be worse than one that only tells you the truth. The output is a report you
act on.

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

# Security audit: same probes + a risk report over the live tool surface
mcp-fleet-doctor audit --client claude
mcp-fleet-doctor audit --config ./my_agent/config.yaml --strict     # CI gate: fail on HIGH/CRIT
mcp-fleet-doctor audit --config mcp.json --track                    # + tool-surface drift baseline
mcp-fleet-doctor audit --config mcp.json --json | jq '.risk.counts'
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
terminated after the probe. The single exception is opt-in state — `audit
--track` writes a tool-surface baseline file (and nothing else on disk).

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

The `audit` command reuses exactly this flow — same spawn, same handshake, same
deadlines — and then scores the tool definitions captured at the `tools/list`
step, plus the config-only checks that need no spawn at all.

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
hanging, missing-command, and deliberately risky — so every verdict class and
every audit finding class is exercised for real, including the guarantee that
an environment value never reaches the report:

```bash
python -m unittest discover -s tests -t .
```

`examples/` contains the matrix as runnable servers plus config files in both
formats; point `--config` at them to see all verdicts in one run. The audit
demo is one command:

```bash
python -m mcp_fleet_doctor.cli audit --config examples/claude_config_with_risky.json
```

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

- v0.3: HTTP/SSE verdicts; `--fix` hints (e.g. "pip install X into venv python Y" extracted live from the crash)
- v0.4: `watch` mode; a cron recipe in the README; Prometheus-ready `--json` schema versioning; more audit vocabulary (nested schemas, resource/prompt surface, not just tools)

## License

MIT — see [LICENSE](LICENSE).
