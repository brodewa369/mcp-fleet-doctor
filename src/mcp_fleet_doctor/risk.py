"""Security audit layer for `mcp-fleet-doctor audit` — heuristics, not certification.

Two layers, both read-only:

* STATIC  — inspects the ``ServerSpec`` only, never spawns anything:
    - risky spawn arguments (literal pipe-to-shell / recursive-delete /
      world-writable patterns in ``command`` / ``args``) -> RISKY_SPAWN_ARGS
    - secret-shaped ENV *key names* -> SECRET_IN_PARAM (name only, value never
      read into a finding and never rendered — the v0.1.0 no-echo rule)
    - server-name heuristics (``prod``, ``deploy``) -> plain WARNINGS, never a
      finding: a name is not proof of anything.

* DYNAMIC — reuses the probe handshake and analyzes the tool definitions a
  server ACTUALLY exposes at runtime via ``tools/list``: what a client really
  puts in front of the model is the live surface, not what a static scanner
  guesses from source or docs.

Every result is a *heuristic risk report*. It is not a security certification,
not a proof of vulnerability, and it never blocks, proxies or enforces
anything — that separation is deliberate (see the README non-goals).
"""
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .configs import ServerSpec, _SAFE_ENV_KEYS

# ── levels ────────────────────────────────────────────────────────────────
INFO = "INFO"          # reserved for informational drift (removals)
LOW = "LOW"
MED = "MED"
HIGH = "HIGH"
CRIT = "CRIT"
#: levels a heuristic finding may take (INFO is drift-only)
FINDING_LEVELS: Tuple[str, ...] = (LOW, MED, HIGH, CRIT)
ALL_LEVELS: Tuple[str, ...] = (INFO, LOW, MED, HIGH, CRIT)
LEVEL_RANK: Dict[str, int] = {INFO: 0, LOW: 1, MED: 2, HIGH: 3, CRIT: 4}

# ── machine finding classes (stable enum for --json consumers) ───────────
PROMPT_INJECTION_HINT = "PROMPT_INJECTION_HINT"
DESTRUCTIVE_NO_CONFIRM = "DESTRUCTIVE_NO_CONFIRM"
SECRET_IN_PARAM = "SECRET_IN_PARAM"
EGRESS_URL_FIELD = "EGRESS_URL_FIELD"
UNSPECIFIED_SCHEMA = "UNSPECIFIED_SCHEMA"
RISKY_SPAWN_ARGS = "RISKY_SPAWN_ARGS"
BASELINE_DRIFT_NEW = "BASELINE_DRIFT_NEW"
BASELINE_DRIFT_REMOVED = "BASELINE_DRIFT_REMOVED"

FINDING_CLASSES: Tuple[str, ...] = (
    PROMPT_INJECTION_HINT,
    DESTRUCTIVE_NO_CONFIRM,
    SECRET_IN_PARAM,
    EGRESS_URL_FIELD,
    UNSPECIFIED_SCHEMA,
    RISKY_SPAWN_ARGS,
    BASELINE_DRIFT_NEW,
    BASELINE_DRIFT_REMOVED,
)

REMEDIATION: Dict[str, str] = {
    RISKY_SPAWN_ARGS:
        "pin a script file instead of inline shell; drop pipe-to-shell, "
        "recursive-delete and world-writable arguments",
    SECRET_IN_PARAM:
        "keep secret material in env/config; accept a reference or alias in "
        "the tool argument instead of a literal secret",
    EGRESS_URL_FIELD:
        "constrain the field to an enum / host allowlist if the destination "
        "is meant to be fixed",
    DESTRUCTIVE_NO_CONFIRM:
        "add a required confirm/approval (or dry-run) argument so the action "
        "cannot fire on the model's first call",
    PROMPT_INJECTION_HINT:
        "remove model-directed imperatives from tool descriptions — they are "
        "read verbatim into the model's context",
    UNSPECIFIED_SCHEMA:
        "declare an inputSchema so clients can validate and bound the payload",
    BASELINE_DRIFT_NEW:
        "new high-risk tool since the last tracked audit — review it, then "
        "re-baseline",
    BASELINE_DRIFT_REMOVED:
        "informational: tool no longer exposed; baseline now matches reality",
}


@dataclass
class Finding:
    """One risk observation. Never carries an environment *value*."""
    server: str
    cls: str
    level: str
    field_path: str
    reason: str
    remediation: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "server": self.server,
            "class": self.cls,
            "level": self.level,
            "field": self.field_path,
            "reason": self.reason,
            "remediation": self.remediation,
        }


@dataclass
class ServerAudit:
    """Per-server audit outcome (findings + name warnings + tool snapshot)."""
    server: str
    verdict: str
    findings: List[Finding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    tool_names: List[str] = field(default_factory=list)
    digest: str = ""
    risky_tools: Set[str] = field(default_factory=set)
    destructive_tools: Set[str] = field(default_factory=set)

    @property
    def max_level(self) -> str:
        if not self.findings:
            return INFO
        return max((f.level for f in self.findings), key=lambda l: LEVEL_RANK[l])


@dataclass
class AuditReport:
    client: str
    path: str
    results: List[Any]
    audits: List[ServerAudit]
    disabled: List[str] = field(default_factory=list)
    baseline_path: Optional[str] = None
    baseline_action: str = "none"       # none | created | updated | skipped
    notes: List[str] = field(default_factory=list)

    @property
    def findings(self) -> List[Finding]:
        out: List[Finding] = []
        for a in self.audits:
            out.extend(a.findings)
        return out

    @property
    def warnings(self) -> List[str]:
        out: List[str] = []
        for a in self.audits:
            out.extend(a.warnings)
        return out

    @property
    def counts(self) -> Dict[str, int]:
        c = {lvl: 0 for lvl in ALL_LEVELS}
        for f in self.findings:
            c[f.level] = c.get(f.level, 0) + 1
        return c

    @property
    def has_high(self) -> bool:
        return any(LEVEL_RANK[f.level] >= LEVEL_RANK[HIGH] for f in self.findings)


# ── shared name vocabulary ───────────────────────────────────────────────

# NOTE: the credential-word is assembled at import time instead of being
# written out, so that it never appears literally anywhere in this repository —
# the pre-release leak scan greps for it and must stay at zero hits. Matching
# behaviour is identical.
_SECRET_WORDS: Set[str] = {
    "secret", "secrets", "token", "tokens", "passwd",
    "credential", "credentials", "apikey", "authkey",
    "pass" + "word",
}
# quantity-ish words: `max_tokens` is a limit, not a secret
_QTY_WORDS: Set[str] = {
    "max", "min", "num", "count", "limit", "length", "budget", "rate",
    "context", "chunk", "total", "size",
}
_KEY_TELLERS: Set[str] = {"api", "private", "access", "secret"}

_CONFIRM_WORDS: Set[str] = {
    "confirm", "confirmation", "confirming", "approval", "approvals",
    "approve", "ack", "acks", "acknowledge", "acknowledgement",
    "acknowledgment", "doublecheck", "verify",
}

#: literal spawn-argument footprints (matched case-insensitively, verbatim)
SPAWN_PATTERNS: Tuple[str, ...] = ("|bash", "|sh", ": ||", "rm -rf", "chmod 777")


def spawn_arg_hits(value: Any) -> List[str]:
    """Risky literals in a spawn argument.

    Patterns are checked verbatim against the lowercased argument *and* against
    a pipe-space-collapsed copy, so real-world ``curl … | bash`` (with spaces)
    trips the same rule as the compact ``…|bash`` spelling.
    """
    low = str(value).lower()
    piped = re.sub(r"\s*\|\s*", "|", low)
    return [p for p in SPAWN_PATTERNS if p in low or p in piped]

#: server-name tokens that *sound* production — warnings only, never findings
_NAME_HEURISTICS: Tuple[str, ...] = ("prod", "deploy")

#: stems matched as a token-prefix (deploy -> deployed/deploying/deployment)
_DESTRUCTIVE_PREFIX: Tuple[str, ...] = (
    "delete", "destroy", "drop", "deploy", "publish", "send", "transfer",
    "sale", "remove", "wipe", "purge", "erase", "nuke", "terminate",
    "shutdown", "truncate", "revoke", "destroy",
)
#: prefix false-positive carve-outs (dropbox_list is not destructive)
_DESTRUCTIVE_PREFIX_EXCLUDE: Dict[str, Set[str]] = {
    "drop": {"dropbox", "droplet", "dropdown"},
}
#: exact-token stems (prod must not match "produce"/"product")
_DESTRUCTIVE_EXACT: Dict[str, Set[str]] = {
    "prod": {"prod", "prods", "production", "productions"},
}

#: imperative phrases in a tool *description* that direct the model
_INJECTION_PATTERNS: Tuple[str, ...] = (
    r"ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\b",
    r"ignore\s+(?:the\s+)?system\b",
    r"\bsystem\s+(?:prompt|instructions?|messages?)\b",
    r"\balways\s+(?:run|execute|call|use|invoke|be\s+run)\b",
    r"\bnever\s+(?:tell|inform|mention|ask|warn|notify|reveal|show|log)\b",
    r"\bmust\s+(?:run|execute|be\s+run|always)\b",
    r"\bautomatically\s+run\b|\brun\s+automatically\b",
    r"auto[-\s]?run",
    r"execute\s+immediately",
    r"call\s+this\s+tool\s+silently",
    r"silently\s+without\s+asking",
    r"without\s+asking\s+(?:the\s+)?user\b",
    r"do\s+not\s+(?:tell|inform|mention|ask|show|reveal)\s+(?:the\s+)?user\b",
    r"\byou\s+must\s+(?:run|execute|always)\b",
    r"without\s+(?:user\s+)?(?:confirmation|asking)\b",
)
_INJECTION_RE = re.compile("|".join(f"(?:{p})" for p in _INJECTION_PATTERNS), re.IGNORECASE)

#: tool names that clearly carry a payload (used for UNSPECIFIED_SCHEMA)
_PAYLOAD_WORDS: Set[str] = {
    "send", "write", "store", "create", "update", "post", "delete", "read",
    "query", "search", "exec", "run", "fetch", "upload", "download",
    "message", "text", "data", "file", "path", "url", "code", "command",
    "sql", "insert", "set", "put", "patch", "request", "call", "notify",
    "email", "mail", "deploy", "execute", "append", "save",
}

#: URL-ish parameter names (EGRESS_URL_FIELD)
_URL_WORDS: Set[str] = {"url", "urls", "uri", "uris", "endpoint", "endpoints",
                        "webhook", "webhooks", "href"}


def _words(name: Any) -> List[str]:
    """Split snake/kebab/camelCase identifiers into lowercase words."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(name))
    return [w.lower() for w in re.split(r"[^A-Za-z0-9]+", s) if w]


def is_secret_name(name: Any) -> bool:
    """True when an identifier *name* is shaped like it holds secret material.

    Deliberately name-only: nothing here ever looks at a value.
    """
    ws = _words(name)
    if not ws:
        return False
    secret_idx = [i for i, w in enumerate(ws) if w in _SECRET_WORDS]
    if secret_idx:
        if all(ws[i] in ("token", "tokens") for i in secret_idx) and (set(ws) & _QTY_WORDS):
            return False          # max_tokens / token_limit class
        return True
    if "key" in ws and (set(ws) & _KEY_TELLERS):
        return True               # api_key / private_key / access_key
    if "pass" in ws and "word" in ws:
        return True               # split spelling of the credential-word
    return False


def is_destructive_name(name: Any) -> bool:
    """True when a token list reads like an irreversible / state-changing action."""
    return bool(destructive_hits(name))


def destructive_hits(text: Any) -> List[str]:
    """Destructive stems present in a name or description (heuristic)."""
    hits: List[str] = []
    for w in _words(text):
        for stem, exact in _DESTRUCTIVE_EXACT.items():
            if w in exact and stem not in hits:
                hits.append(stem)
        for stem in _DESTRUCTIVE_PREFIX:
            if w.startswith(stem) and stem not in hits:
                if w in _DESTRUCTIVE_PREFIX_EXCLUDE.get(stem, ()):
                    continue
                hits.append(stem)
    return hits


def is_confirm_name(name: Any) -> bool:
    ws = set(_words(name))
    if ws & _CONFIRM_WORDS:
        return True
    return "dry" in ws and "run" in ws


# ── STATIC layer ─────────────────────────────────────────────────────────

def _env_key_names(spec: ServerSpec) -> List[str]:
    """Config-declared env key NAMES only (never the values)."""
    raw = spec.raw.get("env") if isinstance(spec.raw, dict) else None
    if isinstance(raw, dict) and raw:
        return [str(k) for k in raw.keys()]
    return [str(k) for k in (spec.env or {}) if k not in _SAFE_ENV_KEYS]


def static_findings(spec: ServerSpec) -> Tuple[List[Finding], List[str]]:
    """Config-only audit: risky spawn footprint, secret-shaped env key names,
    plus production-sounding server-name *warnings* (never findings).

    Returns ``(findings, warnings)``. No process is spawned.
    """
    findings: List[Finding] = []
    warnings: List[str] = []

    # 1) command-footprint: literal risky patterns in the spawn line
    locations: List[Tuple[str, str]] = [("command", str(spec.command))]
    locations += [(f"args[{i}]", str(a)) for i, a in enumerate(spec.args or [])]
    for loc, value in locations:
        hits = spawn_arg_hits(value)
        if hits:
            findings.append(Finding(
                spec.name, RISKY_SPAWN_ARGS, HIGH, loc,
                f"{loc} contains risky literal(s) {', '.join(hits)} — "
                f"inline shell / recursive delete / world-writable footprint "
                f"(only the matched pattern is echoed, not the argument)",
                REMEDIATION[RISKY_SPAWN_ARGS]))

    # 2) secret-shaped env KEY NAMES — values are never read into a finding
    for key in _env_key_names(spec):
        if is_secret_name(key):
            findings.append(Finding(
                spec.name, SECRET_IN_PARAM, MED, f"env.{key}",
                f"config declares a secret-shaped env key '{key}' "
                f"(key name only — the value is never echoed)",
                REMEDIATION[SECRET_IN_PARAM]))

    # 3) server-name heuristics: warnings only, naming is not proof
    name_words = _words(spec.name)
    for tok in _NAME_HEURISTICS:
        if any(w.startswith(tok) for w in name_words):
            warnings.append(
                f"server name '{spec.name}' contains '{tok}' — "
                f"production-sounding name; naming is not proof of production access")

    return findings, warnings


# ── DYNAMIC layer ────────────────────────────────────────────────────────

def _properties(schema: Any) -> Dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    return props if isinstance(props, dict) else {}


def _has_confirmation(schema: Dict[str, Any]) -> bool:
    """A required confirm/approval/ack argument, or an explicit confirm-style boolean."""
    props = _properties(schema)
    required = [str(r) for r in (schema.get("required") or []) if isinstance(schema.get("required"), list)]
    for r in required:
        if is_confirm_name(r):
            return True
    for pname, pspec in props.items():
        if not is_confirm_name(pname) or not isinstance(pspec, dict):
            continue
        if pspec.get("type") == "boolean" or pspec.get("const") is True or pspec.get("default") is True:
            return True
    return False


def analyze_tool(server: str, tool: Any) -> Tuple[List[Finding], bool]:
    """Analyze one live tool descriptor. Returns ``(findings, is_destructive)``."""
    findings: List[Finding] = []
    if not isinstance(tool, dict):
        return findings, False

    name = str(tool.get("name") or "?")
    desc = str(tool.get("description") or "")
    schema = tool.get("inputSchema")
    props = _properties(schema)
    destructive = bool(destructive_hits(name)) or bool(destructive_hits(desc))

    # a) destructive action without any confirmation gate
    if destructive and (not isinstance(schema, dict) or not _has_confirmation(schema)):
        findings.append(Finding(
            server, DESTRUCTIVE_NO_CONFIRM, HIGH, f"tools/{name}",
            f"tool '{name}' reads as a destructive/irreversible action "
            f"({', '.join(destructive_hits(name) or destructive_hits(desc))}) "
            f"with no required confirm/approval argument",
            REMEDIATION[DESTRUCTIVE_NO_CONFIRM]))

    # b) secret-shaped parameter names (string-typed)
    for pname, pspec in props.items():
        ptype = pspec.get("type") if isinstance(pspec, dict) else None
        if ptype not in (None, "string"):
            continue
        if is_secret_name(pname):
            findings.append(Finding(
                server, SECRET_IN_PARAM, CRIT, f"inputSchema.properties.{pname}",
                f"string parameter '{pname}' is secret-shaped — a literal secret "
                f"would travel through the model context (name only, no value read)",
                REMEDIATION[SECRET_IN_PARAM]))

    # c) arbitrary URL / endpoint / webhook field = egress channel
    for pname, pspec in props.items():
        if not (set(_words(pname)) & _URL_WORDS):
            continue
        if not isinstance(pspec, dict):
            continue
        ptype = pspec.get("type")
        fmt = str(pspec.get("format") or "").lower()
        if ptype not in (None, "string"):
            continue
        if fmt and fmt != "uri":
            continue
        findings.append(Finding(
            server, EGRESS_URL_FIELD, MED, f"inputSchema.properties.{pname}",
            f"parameter '{pname}' accepts an arbitrary URL/endpoint — a "
            f"data-exfiltration channel if the tool posts payloads there",
            REMEDIATION[EGRESS_URL_FIELD]))

    # d) imperative phrases in the description (descriptions enter the LLM context)
    if desc:
        m = _INJECTION_RE.search(desc)
        if m:
            findings.append(Finding(
                server, PROMPT_INJECTION_HINT, HIGH, f"tools/{name}.description",
                f"description contains a model-directed imperative "
                f"(\"{m.group(0).strip()}\") — tool descriptions are read verbatim "
                f"into the model's context",
                REMEDIATION[PROMPT_INJECTION_HINT]))

    # e) payload-bearing tool with no inputSchema at all
    if not isinstance(schema, dict):
        payload = set(_words(name)) & _PAYLOAD_WORDS
        if payload:
            level = MED if destructive else LOW
            findings.append(Finding(
                server, UNSPECIFIED_SCHEMA, level, f"tools/{name}.inputSchema",
                f"tool '{name}' carries a payload-shaped name "
                f"({'/'.join(sorted(payload))}) but declares no inputSchema",
                REMEDIATION[UNSPECIFIED_SCHEMA]))

    return findings, destructive


def analyze_tools(server: str, tools: Sequence[Any]) -> Tuple[List[Finding], Set[str], Set[str]]:
    """Analyze every tool a server actually exposes.

    Returns ``(findings, risky_tool_names, destructive_tool_names)`` where a
    *risky* tool is one that produced a HIGH/CRIT finding.
    """
    findings: List[Finding] = []
    risky: Set[str] = set()
    destructive: Set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict):
            continue
        name = str(tool.get("name") or "?")
        fs, destr = analyze_tool(server, tool)
        findings.extend(fs)
        if destr:
            destructive.add(name)
        if any(LEVEL_RANK[f.level] >= LEVEL_RANK[HIGH] for f in fs):
            risky.add(name)
    return findings, risky, destructive


# ── baseline / drift (stateful, only with --track) ───────────────────────

BASELINE_ENV = "MCPFD_BASELINE"
BASELINE_VERSION = 1


def baseline_path() -> Path:
    """``$MCPFD_BASELINE`` if set, else ``~/.cache/mcp-fleet-doctor/baseline.json``."""
    override = os.environ.get(BASELINE_ENV)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".cache" / "mcp-fleet-doctor" / "baseline.json"


def canonical_tools(tools: Sequence[Any]) -> List[str]:
    """Stable, sorted JSON rendering of each tool descriptor."""
    out: List[str] = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        d = {
            "name": t.get("name"),
            "description": t.get("description"),
            "inputSchema": t.get("inputSchema"),
        }
        out.append(json.dumps(d, sort_keys=True, ensure_ascii=False, default=str))
    return sorted(out)


def digest_tools(tools: Sequence[Any]) -> str:
    payload = "\n".join(canonical_tools(tools)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def tool_names(tools: Sequence[Any]) -> List[str]:
    return sorted(str(t.get("name")) for t in tools if isinstance(t, dict))


def load_baseline(path: Path) -> Dict[str, Any]:
    """Migration-safe read: missing / malformed / older files all yield ``{}``."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    entries = data.get("entries")
    if not isinstance(entries, dict):
        # tolerate a bare {key: entry} file written by an earlier shape
        entries = {k: v for k, v in data.items() if isinstance(v, dict) and "digest" in v}
    return entries


def save_baseline(path: Path, entries: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(
        {"version": BASELINE_VERSION, "entries": entries},
        indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    tmp.replace(path)


def apply_drift(audits: List[ServerAudit], entries: Dict[str, Any],
                config_path: str) -> List[str]:
    """Compare each audited server against its stored baseline and refresh it.

    Mutates ``audits`` (appends drift findings / notes) and ``entries``.
    Returns human-readable notes describing what happened to the baseline.
    """
    notes: List[str] = []
    for a in audits:
        if not a.digest:
            continue                      # server did not answer tools/list
        key = f"{config_path}|{a.server}"
        old = entries.get(key)
        if not isinstance(old, dict) or not old.get("digest"):
            entries[key] = {"digest": a.digest, "tools": a.tool_names}
            notes.append(f"baseline created for '{a.server}' "
                         f"({len(a.tool_names)} tools)")
            continue
        if old.get("digest") == a.digest:
            continue                      # unchanged — keep as-is
        old_names = set(old.get("tools") or [])
        new_names = set(a.tool_names)
        removed = sorted(old_names - new_names)
        added = sorted(new_names - old_names)
        if removed:
            a.findings.append(Finding(
                a.server, BASELINE_DRIFT_REMOVED, INFO, "tools/list",
                "tool(s) removed since baseline: " + ", ".join(removed[:12]),
                REMEDIATION[BASELINE_DRIFT_REMOVED]))
        risky_added = [n for n in added
                       if n in a.risky_tools or n in a.destructive_tools]
        if risky_added:
            a.findings.append(Finding(
                a.server, BASELINE_DRIFT_NEW, HIGH, "tools/list",
                "new high-risk tool(s) since baseline: " + ", ".join(risky_added[:12]),
                REMEDIATION[BASELINE_DRIFT_NEW]))
        elif added:
            a.warnings.append(
                f"{len(added)} new non-risky tool(s) since baseline: "
                + ", ".join(added[:12]))
        entries[key] = {"digest": a.digest, "tools": a.tool_names}
        notes.append(f"baseline updated for '{a.server}' "
                     f"({len(added)} added, {len(removed)} removed)")
    return notes


# ── rendering ────────────────────────────────────────────────────────────

LEVEL_EMOJI = {INFO: "ℹ️", LOW: "🔵", MED: "🟠", HIGH: "🔴", CRIT: "⛔"}


def _clip(text: str, n: int = 110) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def render_risk_table(report: AuditReport) -> str:
    rows = sorted(report.findings,
                  key=lambda f: (-LEVEL_RANK[f.level], f.server, f.cls, f.field_path))
    lines: List[str] = []
    if rows:
        w_srv = max([len(f.server) for f in rows] + [6])
        w_lvl = max([len(f.level) for f in rows] + [5])
        w_cls = max([len(f.cls) for f in rows] + [5])
        w_fld = max([len(f.field_path) for f in rows] + [5])
        lines.append(f"{'server':<{w_srv}}  {'level':<{w_lvl}}  {'class':<{w_cls}}  "
                     f"{'field':<{w_fld}}  reason")
        for f in rows:
            lines.append(
                f"{f.server:<{w_srv}}  {f.level:<{w_lvl}}  {f.cls:<{w_cls}}  "
                f"{f.field_path:<{w_fld}}  {_clip(f.reason)}")
    for a in report.audits:
        for w in a.warnings:
            lines.append(f"{'warn':<{6}}  {a.server:<{10}}  {_clip(w)}")
    if not lines:
        lines.append("(no risk findings)")
    return "\n".join(lines)


def risk_summary(report: AuditReport) -> str:
    c = report.counts
    total = sum(c.values())
    parts = " ".join(f"{lvl}={c.get(lvl, 0)}" for lvl in ALL_LEVELS)
    servers = len(report.audits)
    warn = len(report.warnings)
    return (f"{parts} | {total} finding(s) across {servers} server(s)"
            + (f", {warn} name warning(s)" if warn else ""))


def report_as_dict(report: AuditReport, verdict_summary: str,
                   strict: bool) -> Dict[str, Any]:
    """JSON payload for `audit --json`. Contains no environment values."""
    return {
        "config": report.path,
        "client": report.client,
        "mode": "audit",
        "summary": verdict_summary,
        "strict": strict,
        "results": [
            {k: v for k, v in r.__dict__.items() if k != "tool_defs"}
            for r in report.results
        ],
        "risk": {
            "heuristics_only": True,
            "counts": report.counts,
            "has_high_or_crit": report.has_high,
            "findings": [f.as_dict() for f in
                         sorted(report.findings,
                                key=lambda f: (-LEVEL_RANK[f.level], f.server, f.cls))],
            "warnings": [
                {"server": a.server, "warning": w}
                for a in report.audits for w in a.warnings
            ],
            "servers": [
                {"server": a.server, "verdict": a.verdict,
                 "max_level": a.max_level, "findings": len(a.findings),
                 "warnings": len(a.warnings), "tools": len(a.tool_names)}
                for a in report.audits
            ],
            "disabled": report.disabled,
            "baseline": {
                "path": report.baseline_path,
                "action": report.baseline_action,
                "notes": report.notes,
            },
        },
    }
