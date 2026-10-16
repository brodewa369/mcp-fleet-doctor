#!/usr/bin/env python3
"""Example *healthy* MCP server for the doctor's test matrix.

Speaks the newline-delimited stdio dialect: initialize → notifications/initialized
→ tools/list. Lists two sample tools. Run directly; no dependencies.
"""
import json
import sys


def main():
    while True:
        line = sys.stdin.readline()
        if not line:
            return
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        method = req.get("method", "")
        if method == "initialize":
            out = {"jsonrpc": "2.0", "id": req.get("id"),
                   "result": {"protocolVersion": "2024-11-05",
                              "capabilities": {"tools": {}},
                              "serverInfo": {"name": "example-ok", "version": "1.0"}}}
        elif method == "tools/list":
            tools = [
                {"name": "echo",
                 "description": "echo text back",
                 "inputSchema": {"type": "object",
                                 "properties": {"text": {"type": "string"}},
                                 "required": ["text"]}},
                {"name": "uuid",
                 "description": "return a fresh uuid4 string",
                 "inputSchema": {"type": "object", "properties": {}}},
            ]
            out = {"jsonrpc": "2.0", "id": req.get("id"), "result": {"tools": tools}}
        else:
            if req.get("id") is None:      # notification (e.g. notifications/initialized)
                continue
            out = {"jsonrpc": "2.0", "id": req.get("id"),
                   "error": {"code": -32601, "message": f"Unknown method: {method}"}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
