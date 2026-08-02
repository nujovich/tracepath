#!/usr/bin/env python3
"""Faro → Tracepath audit bridge.

After each tool call, Faro sends an audit event to the Tracepath gateway.
This script wraps that interaction — call it with tool metadata after each invocation.
"""

import json
import os
import sys
import time
import uuid
from urllib.request import Request, urlopen
from urllib.error import URLError

GATEWAY_URL = os.environ.get("TRACEPATH_GATEWAY", "http://localhost:9001")
SESSION_ID = f"faro-{uuid.uuid4().hex[:8]}"
AGENT_ID = "faro"
AGENT_TYPE = "assistant"

STEP = 0


def audit_step(tool_name: str, tool_input: dict, tool_output: dict):
    global STEP
    STEP += 1
    payload = {
        "session_id": SESSION_ID,
        "agent_id": AGENT_ID,
        "agent_type": AGENT_TYPE,
        "step_number": STEP,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_output": tool_output,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        req = Request(
            f"{GATEWAY_URL}/audit/step",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        resp = urlopen(req, timeout=5)
        result = json.loads(resp.read())
        sig = result.get("signature", "?")[:16]
        decision = result.get("policy_decision", {})
        status = "ALLOWED" if decision.get("allowed") else "DENIED"
        print(f"[tracepath] step={STEP} tool={tool_name} {status} sig={sig}...", file=sys.stderr)
        return result
    except URLError as e:
        print(f"[tracepath] ERROR: gateway unreachable ({e})", file=sys.stderr)
        return None


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <tool_name> '<json_input>' '<json_output>'")
        sys.exit(1)

    tool = sys.argv[1]
    inp = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
    out = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {}
    result = audit_step(tool, inp, out)
    if result:
        print(json.dumps(result))