#!/usr/bin/env python3
"""Example *broken* MCP server #1 — DELAYED MISSING-DEPENDENCY CRASH.

Starts, waits for the initialize request, THEN dies because a module the server
needs is not installed in its interpreter. This is the nasty silent class:
hunt logs, not chat, to find the reason. The doctor reproduces it live and
reports the exact missing module.
"""
import json
import sys
import time

sys.stderr.write("example-missing-deps: boot ok, loading heavy runtime...\n")
sys.stderr.flush()
try:
    import some_module_that_does_not_exist  # noqa: F401
except ModuleNotFoundError as e:            # deliberate: exact failure class
    sys.stderr.write(str(e) + "\n")
    sys.stderr.flush()
    sys.exit(3)
