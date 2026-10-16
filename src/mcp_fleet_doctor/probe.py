"""Live probe: spawn a configured server and speak MCP stdio to it.

Mirrors what a real MCP client (Claude Desktop, Cursor, Hermes …) does:
  1. spawn process with config env (safe base env + client env, ${VAR} expanded)
  2. send `initialize`, await the response by ID
  3. send `notifications/initialized` (its error — if the server even rejects it — is not fatal)
  4. send `tools/list`, count the tools
  5. classify the outcome into a verdict with an actionable reason parsed from
     the server's own stderr (ModuleNotFoundError, tracebacks, bare-command miss)

Production lessons baked in:
- stdout is read via select() with a deadline — a server that starts and then
  never speaks MCP must time out, never hang the doctor.
- responses are matched by request id, not read sequentially — real servers
  inject noise (unknown-method errors, logs-as-JSON) at the worst moments.
- the initialized notification is sent but its response/ERROR is never waited on.
- I/O is binary + manual decode; some servers emit non-text bytes.
- Subprocess I/O is Windows-unfriendly POSIX select; Linux/macOS only in v1.
"""
import json
import os
import re
import select
import shutil
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

VER_OK = "OK"
VER_NO_TOOLS = "CONNECTED_BUT_NO_TOOLS"
VER_UNRESPONSIVE = "STARTED_BUT_NO_RESPONSE"
VER_CRASHED = "CRASHED_ON_STARTUP"
VER_CMD_MISSING = "COMMAND_NOT_FOUND"
VER_ERROR = "PROBE_ERROR"

_MODULE_ERR_RE = re.compile(
    r"ModuleNotFoundError:\s*No module named\s+'([^']+)'|ImportError:\s*(?:[^\n]*?from\s+)?'([^']+)'(?::\d+)?",
    re.IGNORECASE,
)


@dataclass
class ProbeResult:
    server: str
    verdict: str
    detail: str = ""
    tools: int = 0
    missing_module: Optional[str] = None
    stderr_tail: List[str] = field(default_factory=list)
    exit_code: Optional[int] = None
    probe_ms: Optional[int] = None


def _stderr_drain(stream, tail: deque) -> None:
    """Drain a binary stderr stream into the shared deque until EOF."""
    try:
        for line in iter(stream.readline, b""):
            tail.append(line.decode(errors="replace").rstrip())
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            stream.close()
        except Exception:  # noqa: BLE001
            pass


def _classify_stderr(tail: deque) -> Tuple[Optional[str], str]:
    joined = "\n".join(tail)
    m = re.search(r"No module named\s+'([^']+)'", joined)
    if not m:
        m = re.search(r"ImportError:[^\n]*?'([^']+)'", joined)
    if m:
        missing = m.group(1)
        return missing, f"missing module '{missing}' in that interpreter — pin the python + install it"
    if "Traceback" in joined:
        last = tail[-1] if tail else ""
        return None, f"traceback: {last[:180]}"
    if re.search(r"Address already in use|EADDRINUSE", joined):
        return None, "port already in use"
    if tail:
        return None, f"stderr: {[l for l in tail if l.strip()][-1][:180]}"
    return None, ""


def probe(spec, startup_timeout: float = 10.0, handshake_timeout: float = 20.0,
          call_timeout: float = 30.0) -> ProbeResult:
    """Full live probe for one ServerSpec. Always returns; never hangs past sum of timeouts."""
    name = spec.name
    resolved = shutil.which(spec.command) if "/" not in spec.command else spec.command
    if resolved is None:
        return ProbeResult(
            name, VER_CMD_MISSING,
            detail=f"command '{spec.command}' not found on PATH — pin an absolute path "
                   f"or install it where the client resolves PATH",
        )

    cmd = [resolved] + [str(a) for a in spec.args if a]
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=spec.env, cwd=spec.cwd or None, shell=False)
    except FileNotFoundError:
        return ProbeResult(name, VER_CMD_MISSING, detail=f"spawn failed: '{spec.command}'")
    except PermissionError:
        return ProbeResult(name, VER_CMD_MISSING, detail=f"spawn failed: '{spec.command}' not executable")

    tail = deque(maxlen=60)
    th = threading.Thread(target=_stderr_drain, args=(proc.stderr, tail), daemon=True)
    th.start()
    try:
        result = _handshake(proc, name, startup_timeout, handshake_timeout, call_timeout, tail, th)
    except Exception as e:  # noqa: BLE001
        result = ProbeResult(name, VER_ERROR, detail=f"internal: {type(e).__name__}: {e}")
    finally:
        _terminate(proc)

    if result is None:
        result = ProbeResult(name, VER_ERROR, detail="no result")
    if not result.stderr_tail:
        result.stderr_tail = list(tail)[-6:]
    result.probe_ms = int((time.monotonic() - t0) * 1000)
    return result


def _terminate(proc: subprocess.Popen) -> None:
    try:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
    except Exception:  # noqa: BLE001
        pass
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
    except Exception:  # noqa: BLE001
        pass


def _send(proc, obj) -> None:
    if proc.stdin is None or proc.stdin.closed:
        raise BrokenPipeError("stdin closed")
    proc.stdin.write((json.dumps(obj) + "\n").encode())
    proc.stdin.flush()


def _read_response(proc, want_id: int, deadline: float, tail: deque) -> Tuple[Optional[dict], bool]:
    """Select()-based newline-delimited JSON-RPC read until response with want_id.

    Returns (message_or_None, eof). eof=True distinguishes «process closed stdout»
    from «we timed out waiting» — different verdicts need different reasons.
    """
    fd = proc.stdout.fileno()
    buf = ""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, False
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            return None, False
        chunk = os.read(fd, 65536)
        if not chunk:
            return None, True        # EOF: process closed stdout
        buf += chunk.decode(errors="replace")
        while "\n" in buf:
            line, buf = buf.split("\n", 1)
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                tail.append(f"[stdout non-JSON] {line[:200]}")
                continue
            if msg.get("id") == want_id:
                return msg, False
            # anything else: notifications / progress / other errors — keep waiting


def _handshake(proc, name, startup_timeout, handshake_timeout, call_timeout, tail, th) -> ProbeResult:
    # 1) initialize
    _send(proc, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "clientInfo": {"name": "mcp-fleet-doctor", "version": "0.1.0"}}})
    resp, eof = _read_response(proc, 1, time.monotonic() + handshake_timeout, tail)
    if resp is None and eof:
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    if resp is None and proc.poll() is not None:
        th.join(timeout=2)
        missing, why = _classify_stderr(tail)
        return ProbeResult(name, VER_CRASHED, detail=why or f"exited (code={proc.returncode}) during initialize",
                           missing_module=missing, exit_code=proc.returncode)
    if resp is None:
        # One retry window for slow initializers (model loading, cold cache):
        resp, eof = _read_response(proc, 1, time.monotonic() + startup_timeout, tail)
        if resp is None and eof:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        if resp is None and proc.poll() is not None:
            th.join(timeout=2)
            missing, why = _classify_stderr(tail)
            return ProbeResult(name, VER_CRASHED, detail=why or f"exited (code={proc.returncode}) during initialize",
                               missing_module=missing, exit_code=proc.returncode)
        if resp is None:
            missing, why = _classify_stderr(tail)
            return ProbeResult(name, VER_UNRESPONSIVE,
                               detail=why or "alive but no response to initialize (hang/daemon class)",
                               missing_module=missing)
    if "error" in resp:
        return ProbeResult(name, VER_CRASHED,
                           detail=f"initialize error: {(resp.get('error') or {}).get('message', '')[:180]}",
                           exit_code=proc.poll())

    # 2) initialized notification — send, never wait
    try:
        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
    except Exception:  # noqa: BLE001
        pass

    # 3) tools/list
    _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    resp2, eof2 = _read_response(proc, 2, time.monotonic() + call_timeout, tail)
    if resp2 is None and eof2:
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
    if resp2 is None:
        if proc.poll() is not None:
            th.join(timeout=2)
            missing, why = _classify_stderr(tail)
            return ProbeResult(name, VER_CRASHED, detail=why or f"exited (code={proc.returncode}) answering tools/list",
                               missing_module=missing, exit_code=proc.returncode)
        return ProbeResult(name, VER_UNRESPONSIVE, detail="received initialize, no answer to tools/list")
    if "error" in resp2:
        return ProbeResult(name, VER_CRASHED,
                           detail=f"tools/list error: {(resp2.get('error') or {}).get('message', '')[:180]}",
                           exit_code=proc.poll())

    result = resp2.get("result") or {}
    tools = result.get("tools") or []
    n = len(tools) if isinstance(tools, list) else 0
    if n == 0:
        return ProbeResult(name, VER_NO_TOOLS,
                           detail="connected + listed 0 tools — server capability issue",
                           exit_code=proc.poll())
    first = ", ".join(sorted(str(t.get("name", "?")) for t in tools)[:6])
    more = f" (+{n-6} more)" if n > 6 else ""
    return ProbeResult(name, VER_OK, detail=f"{n} tools: {first}{more}", tools=n, exit_code=proc.poll())
