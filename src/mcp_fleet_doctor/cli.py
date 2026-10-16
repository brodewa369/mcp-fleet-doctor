"""CLI: `mcp-fleet-doctor [--client ... --config PATH -s NAME]` and `mcp-fleet-doctor audit ...`

Two modes:
    (default)  probe every stdio server in the config, one verdict per server
    `audit`    the same probes PLUS a risk audit: static config findings and a
               spawn-verified analysis of the tool surface each server actually
               exposes at runtime (optional drift tracking with `--track`)

Exit codes (cron/CI friendly):
    0 = every probed server OK
    1 = at least one server not OK (any verdict != OK), or — with `audit
        --strict` — any HIGH/CRIT risk finding
    2 = nothing to probe (no config / no servers) or usage error
"""
import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__, risk
from .configs import load_auto, load_client, static_checks
from .probe import VER_OK, probe

VERDICT_EMOJI = {
    "OK": "✅",
    "CONNECTED_BUT_NO_TOOLS": "🫥",
    "STARTED_BUT_NO_RESPONSE": "🟡",
    "CRASHED_ON_STARTUP": "❌",
    "COMMAND_NOT_FOUND": "🚫",
    "PROBE_ERROR": "💥",
}
ORDER = ["OK", "CONNECTED_BUT_NO_TOOLS", "COMMAND_NOT_FOUND", "CRASHED_ON_STARTUP", "STARTED_BUT_NO_RESPONSE", "PROBE_ERROR"]


def _is_off(spec) -> bool:
    """A switched-off server (`enabled: false` / `disabled: true`) is a config
    choice, not a fault — it is reported but never probed or failed."""
    return (spec.raw.get("enabled") is False) or (spec.raw.get("disabled") is True)


def _pick(client: str, config: Optional[Path], server_filter: Optional[str]):
    cc = load_client(client, config) if config else (
        load_client(client) if client not in ("auto", None) else load_auto())
    if cc is None:
        return None
    servers = [s for s in cc.servers if (not server_filter or s.name == server_filter)]
    cc.servers = servers
    return cc


def _resolve_config(client: str, config: Optional[Path], server_filter: Optional[str]):
    if client == "auto" and config is None:
        cc = load_auto()
    else:
        cc = _pick(client, config, server_filter)
        if cc is None and client == "auto":
            cc = load_auto()
    return cc


def _run(cc, startup_timeout=10.0, handshake_timeout=20.0, call_timeout=30.0):
    """Probe the enabled servers; disabled ones (`enabled: false` / `disabled: true`)
    are returned separately — a switched-off server is a config choice, not a fault."""
    active, disabled_names = [], []
    results = []
    for spec in cc.servers:
        off = _is_off(spec)
        (disabled_names if off else active).append(spec.name)
        if off:
            continue
        warnings = static_checks(spec)
        live = probe(spec, startup_timeout=startup_timeout,
                     handshake_timeout=handshake_timeout, call_timeout=call_timeout)
        note = "; ".join(warnings[:2])
        if live.verdict == "COMMAND_NOT_FOUND" and "not found on PATH" in note:
            note = " | ".join(w for w in warnings[:2] if "NOT found on PATH" not in w)
        live.detail = (live.detail + (" | " + note if note else "")).strip(" |")
        results.append(live)
    return results, disabled_names


def render_table(results) -> str:
    if not results:
        return "(no servers)"
    name_w = max(len(r.server) for r in results) + 2
    ver_w = max(len(r.verdict) for r in results) + 1
    font = []
    for r in sorted(results, key=lambda r: ORDER.index(r.verdict) if r.verdict in ORDER else 9):
        pad = name_w - len(r.server)
        font.append(f"{VERDICT_EMOJI.get(r.verdict, '?')} {r.server: <{pad}} {r.verdict: <{ver_w}} {r.detail}")
    return "\n".join(font)


class VerdictJsonEncoder(json.JSONEncoder):
    def default(self, o):  # noqa: D105
        if hasattr(o, "__dataclass_fields__"):
            return o.__dict__
        return super().default(o)


def _add_common_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-c", "--client", default="auto",
                   choices=["auto", "claude", "cursor", "vscode", "windsurf", "opencode", "hermes"],
                   help="which client's config to audit (default: auto-detect)")
    p.add_argument("--config", type=Path, default=None,
                   help="explicit config file (JSON or YAML), overrides --client default paths")
    p.add_argument("-s", "--server", default=None, help="probe only this named server")
    p.add_argument("--startup-timeout", type=float, default=10.0)
    p.add_argument("--handshake-timeout", type=float, default=20.0)
    p.add_argument("--call-timeout", type=float, default=30.0)
    p.add_argument("--json", action="store_true", help="machine-readable output")


def _usage_error(cc, args) -> Optional[int]:
    """Common guards shared by both modes; returns an exit code or None."""
    if cc is None:
        print("No MCP server config found. Try --config /path/to/config", file=sys.stderr)
        return 2
    if not cc.servers:
        print(f"Config found at {cc.path} but it declares no stdio MCP servers.", file=sys.stderr)
        return 2
    if args.server and not [s for s in cc.servers if s.name == args.server]:
        print(f"Server '{args.server}' not declared in {cc.path}", file=sys.stderr)
        return 2
    return None


def main(argv=None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "audit":
        return audit_main(raw[1:])

    p = argparse.ArgumentParser(
        prog="mcp-fleet-doctor",
        description="Config-level doctor for MCP server fleets: probe every server in your client configs "
                    "the way a real MCP client would and tell you exactly what is broken and why. "
                    "Add the `audit` subcommand for a spawn-verified risk audit of the fleet.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    _add_common_args(p)
    args = p.parse_args(argv)

    cc = _resolve_config(args.client, args.config, args.server)
    err = _usage_error(cc, args)
    if err is not None:
        return err

    results, disabled = _run(cc, startup_timeout=args.startup_timeout,
                             handshake_timeout=args.handshake_timeout, call_timeout=args.call_timeout)
    n_ok = sum(1 for r in results if r.verdict == VER_OK)
    summary = f"{n_ok}/{len(results)} OK" + (f", {len(disabled)} disabled skipped" if disabled else "")
    if args.json:
        # tool_defs (the full live tool surface) is audit-only payload
        slim = [{k: v for k, v in r.__dict__.items() if k != "tool_defs"} for r in results]
        print(json.dumps(
            {"config": str(cc.path), "client": cc.client, "summary": summary, "results": slim},
            cls=VerdictJsonEncoder, indent=2, ensure_ascii=False))
    else:
        print(f"== mcp-fleet-doctor | client={cc.client} | {cc.path}")
        print(render_table(results))
        print(f"== {summary}")
    return 0 if n_ok == len(results) else 1


def audit_main(argv=None) -> int:
    """`mcp-fleet-doctor audit` — probes plus a spawn-verified risk audit."""
    p = argparse.ArgumentParser(
        prog="mcp-fleet-doctor audit",
        description="Probe every server in the config and audit the risk it carries: "
                    "static config findings (risky spawn arguments, secret-shaped env key NAMES) "
                    "plus a heuristic analysis of the tool definitions each server ACTUALLY "
                    "exposes at runtime. Read-only diagnostics — heuristics, not certification.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    _add_common_args(p)
    p.add_argument("--strict", action="store_true",
                   help="exit 1 when any HIGH/CRIT finding is present (CI gate)")
    p.add_argument("--track", action="store_true",
                   help="compare the live tool surface against the stored baseline and refresh it "
                        "(env MCPFD_BASELINE overrides the baseline file location)")
    p.add_argument("--baseline-file", type=Path, default=None,
                   help="override the drift baseline file location "
                        "(default: $MCPFD_BASELINE, else ~/.cache/mcp-fleet-doctor/baseline.json)")
    args = p.parse_args(argv)

    cc = _resolve_config(args.client, args.config, args.server)
    err = _usage_error(cc, args)
    if err is not None:
        return err

    results, disabled = _run(cc, startup_timeout=args.startup_timeout,
                             handshake_timeout=args.handshake_timeout, call_timeout=args.call_timeout)
    active = [s for s in cc.servers if not _is_off(s)]

    audits = []
    for spec, live in zip(active, results):
        findings, warnings = risk.static_findings(spec)
        names: List[str] = []
        digest = ""
        risky, destructive = set(), set()
        if live.verdict == VER_OK and live.tool_defs:
            names = risk.tool_names(live.tool_defs)
            digest = risk.digest_tools(live.tool_defs)
            dyn, risky, destructive = risk.analyze_tools(spec.name, live.tool_defs)
            findings.extend(dyn)
        audits.append(risk.ServerAudit(
            server=spec.name, verdict=live.verdict, findings=findings,
            warnings=warnings, tool_names=names, digest=digest,
            risky_tools=risky, destructive_tools=destructive))

    report = risk.AuditReport(
        client=cc.client, path=str(cc.path), results=results,
        audits=audits, disabled=disabled)

    if args.track:
        bpath = (Path(args.baseline_file).expanduser() if args.baseline_file
                 else risk.baseline_path())
        report.baseline_path = str(bpath)
        existed = bpath.exists()
        entries = risk.load_baseline(bpath)
        before = json.dumps(entries, sort_keys=True, ensure_ascii=False)
        report.notes = risk.apply_drift(audits, entries, str(cc.path))
        after = json.dumps(entries, sort_keys=True, ensure_ascii=False)
        if before != after:
            risk.save_baseline(bpath, entries)
            report.baseline_action = "updated" if existed else "created"
        else:
            report.baseline_action = "unchanged" if existed else "skipped"
    else:
        report.baseline_action = "disabled"

    n_ok = sum(1 for r in results if r.verdict == VER_OK)
    summary = f"{n_ok}/{len(results)} OK" + (f", {len(disabled)} disabled skipped" if disabled else "")

    if args.json:
        print(json.dumps(risk.report_as_dict(report, summary, args.strict),
                         indent=2, ensure_ascii=False))
    else:
        print(f"== mcp-fleet-doctor audit | client={cc.client} | {cc.path}")
        print(render_table(results))
        print(f"== {summary}")
        print()
        print("== risk table (heuristic — NOT a security certification; no enforcement)")
        print(risk.render_risk_table(report))
        print(f"== {risk.risk_summary(report)}")
        if args.track:
            print(f"== baseline: {report.baseline_action} @ {report.baseline_path}")
            for note in report.notes:
                print(f"   - {note}")

    code = 0 if n_ok == len(results) else 1
    if args.strict and report.has_high:
        code = 1
    return code


if __name__ == "__main__":
    sys.exit(main())
