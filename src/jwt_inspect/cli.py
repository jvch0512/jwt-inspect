from __future__ import annotations

import argparse
import json
import sys

from .core import JWTError, audit, decode, human_times

ORDER = ["critical", "high", "medium", "low", "info"]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="jwt-inspect", description="Decode and audit a JWT offline. Signatures are NOT verified.")
    p.add_argument("token", help="the token, or '-' to read from stdin")
    p.add_argument("--wordlist", help="extra HMAC secrets to try, one per line")
    p.add_argument("--aud", help="expected audience")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--fail-on", choices=ORDER[:-1], default="high")
    a = p.parse_args(argv)
    token = sys.stdin.read().strip() if a.token == "-" else a.token
    words = open(a.wordlist, encoding="utf-8").read().split() if a.wordlist else None
    try:
        header, payload, _, _ = decode(token)
        findings = sorted(audit(token, wordlist=words, expected_aud=a.aud), key=lambda f: ORDER.index(f.severity))
    except JWTError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if a.format == "json":
        print(json.dumps({"header": header, "payload": payload, "times": human_times(payload), "findings": [f.as_dict() for f in findings]}, indent=2))
    else:
        print("HEADER ", json.dumps(header))
        print("PAYLOAD", json.dumps(payload))
        for k, v in human_times(payload).items():
            print(f"  {k}: {v}")
        print()
        for f in findings:
            print(f"[{f.severity.upper():8}] {f.code}: {f.message}")
        if not findings:
            print("no findings")
    return 2 if any(ORDER.index(f.severity) <= ORDER.index(a.fail_on) for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
