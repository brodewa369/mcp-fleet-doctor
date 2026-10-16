"""Load MCP server declarations from the config files of common MCP clients.

All loaders return a uniform structure: ClientConfig(client, path, servers:[ServerSpec]).

Found keys handled per client:
    Claude Desktop / Cursor / WindSurf   -> "mcpServers"
    VS Code (mcp.json)                   -> "servers"
    Hermes (config.yaml)                 -> "mcp_servers"
    generic                              -> any of the above, or flat {name:{command...}}

Security: environment *values* are never echoed by the doctor; only key names
(${VAR} placeholders) are surfaced. Server definitions themselves are public
config. HTTP/SSE `url` entries are skipped in v1.

stdlib-only for JSON configs. YAML uses PyYAML when installed; otherwise a
minimal built-in indentation parser (subset documented in the README) is used.
"""
import os, re, json, shutil, subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

_SAFE_ENV_KEYS = ("PATH", "HOME", "USER", "LANG", "LC_ALL", "TERM", "SHELL", "TMPDIR")
PLACEHOLDER_RE = re.compile(r"\$\{([^}]+)\}")
SERVER_KEYS = ("mcpServers", "mcp_servers", "servers")
BARE_PY_INTERPRETERS = {"python", "python3", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13", "python3.14", "python.exe"}


@dataclass
class ServerSpec:
    name: str
    command: str
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    cwd: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    missing_env: List[str] = field(default_factory=list)


@dataclass
class ClientConfig:
    client: str            # claude|cursor|vscode|windsurf|hermes|opencode|file
    path: Path
    servers: List[ServerSpec] = field(default_factory=list)


# ── 1. static checks (no spawn) ────────────────────────────────────────────

def static_checks(spec: ServerSpec) -> List[str]:
    """Cheap config-level checks. Returns human-readable warnings."""
    warn: List[str] = []
    resolved = shutil.which(spec.command) if "/" not in spec.command else (
        spec.command if Path(spec.command).is_file() else None)
    is_bare_interpreter = spec.command in BARE_PY_INTERPRETERS

    if resolved is None and "/" not in spec.command:
        warn.append(f"command '{spec.command}' NOT found on PATH (would fail to spawn)")
    elif is_bare_interpreter:
        warn.append(
            f"bare interpreter '{spec.command}': resolves per host PATH — "
            f"pin an absolute venv path (silently-wrong-python class)")
    elif resolved is not None:
        # If it's a python interpreter, verify it actually runs (missing deps /
        # wiped venvs show up here as "broken python").
        if Path(resolved).name.startswith("python") or "python" in Path(spec.command).name.lower():
            try:
                subprocess_run_py_ok(resolved)
            except Exception as e:  # noqa: BLE001
                warn.append(f"python '{spec.command}' is broken: {type(e).__name__}: {str(e)[:180]}")

    for m in spec.missing_env:
        warn.append(f"env ${m} referenced in config but not set in this shell")

    if spec.cwd and not Path(spec.cwd).is_dir():
        warn.append(f"working_directory '{spec.cwd}' does not exist")
    return warn


def subprocess_run_py_ok(cmd: str) -> None:
    r = subprocess.run([cmd, "-c", "assert True"], capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or "interpreter exited nonzero").strip()[:200])


# ── 2. env building (values are never echoed) ──────────────────────────────

def build_env(env_cfg: Optional[Dict[str, Any]]) -> "tuple[Dict[str, str], List[str]]":
    base = {k: os.environ[k] for k in _SAFE_ENV_KEYS if k in os.environ}
    out = dict(base)
    missing: List[str] = []

    def _sub(m: "re.Match[str]") -> str:
        name = m.group(1)
        val = os.environ.get(name)
        if val is None:
            missing.append(name)
            return ""
        return val

    for k, v in (env_cfg or {}).items():
        if isinstance(v, bool):
            v = "true" if v else "false"
        if isinstance(v, (int, float)):
            v = str(v)
        out[str(k)] = PLACEHOLDER_RE.sub(_sub, str(v))
    return out, sorted(set(missing))


# ── 3. entry → ServerSpec ──────────────────────────────────────────────────

def _spec_from_entry(name: str, entry: Dict[str, Any], client: str) -> Optional[ServerSpec]:
    if not isinstance(entry, dict):
        return None
    if "url" in entry:  # remote/HTTP server — out of scope in v1
        return None
    cmd = entry.get("command")
    if not cmd:
        return None
    env, missing = build_env(entry.get("env") or {})
    cwd = entry.get("working_directory") or entry.get("cwd")
    return ServerSpec(
        name=str(name),
        command=str(cmd),
        args=[str(a) for a in (entry.get("args") or [])],
        env=env,
        cwd=str(cwd) if cwd else None,
        missing_env=missing,
        raw=entry,
    )


# ── 4. File loaders ─────────────────────────────────────────────────────────

def _load_data(path: Path) -> Dict[str, Any]:
    try:
        txt = path.read_text()
    except OSError:
        return {}
    if path.suffix in (".yaml", ".yml"):
        return _yaml_load(txt)
    try:
        data = json.loads(txt)
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def _yaml_load(txt: str) -> Dict[str, Any]:
    try:
        import yaml                                   # optional dependency
        data = yaml.safe_load(txt)
        return data if isinstance(data, dict) else {}
    except ImportError:
        return _MiniYaml(txt).load()
    except Exception:                                  # malformed yaml
        return {}


class _MiniYaml:
    """Minimal indentation YAML reader (subset): maps, lists, nested blocks, scalars.

    Covers the regular shapes found in tool/mcp client configs. Not a full YAML
    implementation by design — PyYAML handles exotic fonts of YAML when present.
    """

    def __init__(self, text: str):
        self.lines: List[tuple] = []
        for raw in text.splitlines():
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            indent = len(raw) - len(raw.lstrip())
            self.lines.append((indent, raw.strip()))
        self.pos = 0

    def load(self) -> Dict[str, Any]:
        if not self.lines:
            return {}
        val = self._block(self.lines[0][0])
        return val if isinstance(val, dict) else {}

    def _block(self, indent: int) -> Any:
        if self.pos >= len(self.lines):
            return None
        _, content = self.lines[self.pos]
        if content == "-" or content.startswith("- "):
            return self._list(indent)
        return self._map(indent)

    def _map(self, indent: int) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        while self.pos < len(self.lines):
            ln_ind, content = self.lines[self.pos]
            if ln_ind < indent:
                break
            if ln_ind > indent:
                break  # malformed for our subset; stop defensively
            m = re.match(r"^([\"']?)([A-Za-z0-9_.\-/]+)\1\s*:\s*(.*)$", content)
            if not m:
                self.pos += 1
                continue
            key = m.group(2)
            rest = m.group(3)
            if rest == "":
                self.pos += 1
                if self.pos < len(self.lines) and self.lines[self.pos][0] > indent:
                    out[key] = self._block(self.lines[self.pos][0])
                else:
                    out[key] = None
            else:
                out[key] = _scalar(rest)
                self.pos += 1
        return out

    def _list(self, indent: int) -> List[Any]:
        out: List[Any] = []
        while self.pos < len(self.lines):
            ln_ind, content = self.lines[self.pos]
            if ln_ind != indent or not (content == "-" or content.startswith("- ")):
                break
            item = content[2:].strip() if len(content) > 1 else ""
            if item == "":
                self.pos += 1
                if self.pos < len(self.lines) and self.lines[self.pos][0] > indent:
                    out.append(self._block(self.lines[self.pos][0]))
                else:
                    out.append(None)
            elif re.match(r"^([\"']?)([A-Za-z0-9_.\-/]+)\1\s*:\s*", item):
                # "- key: value" starts a map item — re-anchor and parse as map
                self.lines[self.pos] = (indent + 2, item)
                out.append(self._map(indent + 2))
            else:
                out.append(_scalar(item))
                self.pos += 1
        return out


def _scalar(s: str) -> Any:
    s = s.strip()
    if s.startswith(("'", '"')) and len(s) > 1 and s[-1] == s[0]:
        return s[1:-1]
    if s in ("true", "True", "yes"):
        return True
    if s in ("false", "False", "no"):
        return False
    if s in ("null", "~", ""):
        return None
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


CLIENT_DEFAULTS: Dict[str, List[Path]] = {
    "claude":   [
        Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        Path.home() / ".claude" / "claude_desktop_config.json",
    ],
    "cursor":   [Path.home() / ".cursor" / "mcp.json"],
    "vscode":   [Path.home() / ".config" / "Code" / "User" / "mcp.json"],
    "windsurf": [Path.home() / ".codeium" / "windsurf" / "mcp_config.json"],
    "opencode": [Path.home() / ".config" / "opencode" / "opencode.json"],
    "hermes":   [Path.home() / ".hermes" / "config.yaml"],
}


def _extract_servers(data: Dict[str, Any], cc: ClientConfig) -> List[ServerSpec]:
    for key in SERVER_KEYS:
        entries = data.get(key)
        if isinstance(entries, dict):
            servers = [
                _spec_from_entry(str(name), entry, cc.client)
                for name, entry in entries.items()
            ]
            servers = [s for s in servers if s]
            if servers:
                return servers
    # flat style: {"name": {"command": ...}, ...} at top level
    if data and all(isinstance(v, dict) and isinstance(v.get("command"), str) for v in data.values()):
        servers = [_spec_from_entry(k, v, cc.client) for k, v in data.items()]
        return [s for s in servers if s]
    return []


def load_client(client: str, path: Optional[Path] = None) -> Optional[ClientConfig]:
    if path is not None:
        p = Path(path).expanduser()
        if not p.exists():
            return None
        cc = ClientConfig(client="file", path=p)
        cc.servers = _extract_servers(_load_data(p), cc)
        return cc
    for cand in CLIENT_DEFAULTS.get(client, []):
        if cand.exists():
            cc = ClientConfig(client=client, path=cand)
            cc.servers = _extract_servers(_load_data(cand), cc)
            return cc
    return None


def load_auto() -> Optional[ClientConfig]:
    """First existing default config that actually declares servers wins."""
    found = [cc for c in CLIENT_DEFAULTS for cc in [load_client(c)] if cc and cc.servers]
    return max(found, key=lambda c: len(c.servers)) if found else None
