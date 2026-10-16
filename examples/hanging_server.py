#!/usr/bin/env python3
"""Example *broken* MCP server #2 — RUNS FOREVER, NEVER ANSWERS MCP.

This is the 'started but no response' failure class: the process lives, so the
MCP client keeps it parked… but speaking MCP to it gets nothing. The doctor
times out and tells you the server ignored the initialize handshake.
"""
import sys
import time

while True:
    time.sleep(3600.0)   # alive but not MCP; never reads stdin
