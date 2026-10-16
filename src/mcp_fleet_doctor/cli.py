"""CLI: `mcp-fleet-doctor --client claude|cursor|vscode|windsurf|hermes|opencode|auto|file --config PATH -s NAME`

Exit codes (cron/CI friendly):
    0 = every probed server OK
    1 = at least one server not OK (any verdict != OK)
    2 = nothing to probe (no config / no servers) or usage error
"""
import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
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


def _pick(client: str, config: Optional[Path], server_filter: Optional[str]):
    cc = load_client(client, config) if config else (
        load_client(client) if client not in ("auto", None) else load_auto())
    if cc is None:
        return None
    servers = [s for s in cc.servers if (not server_filter or s.name == server_filter)]
    cc.servers = servers
    return cc


def _run(cc, startup_timeout=10.0, handshake_timeout=20.0, call_timeout=30.0):
    """Probe the enabled servers; disabled ones (`enabled: false` / `disabled: true`)
    are returned separately — a switched-off server is a config choice, not a fault."""
    active, disabled_names = [], []
    results = []
    for spec in cc.servers:
        off = (spec.raw.get("enabled") is False) or (spec.raw.get("disabled") is True)
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


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="mcp-fleet-doctor",
        description="Config-level doctor for MCP server fleets: probe every server in your client configs "
                    "the way a real MCP client would and tell you exactly what is broken and why.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
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
    args = p.parse_args(argv)

    if args.client == "auto" and args.config is None:
        cc = load_auto()
    else:
        cc = _pick(args.client, args.config, args.server)
        if cc is None and args.client == "auto":
            cc = load_auto()
    if cc is None:
        print("No MCP server config found. Try --config /path/to/config", file=sys.stderr)
        return 2
    if not cc.servers:
        print(f"Config found at {cc.path} but it declares no stdio MCP servers.", file=sys.stderr)
        return 2
    if args.server:
        if not [s for s in cc.servers if s.name == args.server]:
            print(f"Server '{args.server}' not declared in {cc.path}", file=sys.stderr)
            return 2

    results, disabled = _run(cc, startup_timeout=args.startup_timeout,
                             handshake_timeout=args.handshake_timeout, call_timeout=args.call_timeout)
    n_ok = sum(1 for r in results if r.verdict == VER_OK)
    summary = f"{n_ok}/{len(results)} OK" + (f", {len(disabled)} disabled skipped" if disabled else "")
    if args.json:
        print(json.dumps(
            {"config": str(cc.path), "client": cc.client, "summary": summary, "results": results},
            cls=VerdictJsonEncoder, indent=2, ensure_ascii=False))
    else:
        print(f"== mcp-fleet-doctor | client={cc.client} | {cc.path}")
        print(render_table(results))
        print(f"== {summary}")
    return 0 if n_ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
