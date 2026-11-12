"""Decode and audit JSON Web Tokens WITHOUT verifying signatures. For analysis, not authentication."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass

WEAK_SECRETS = ["secret", "password", "123456", "changeme", "admin", "jwt", "jwtsecret", "your-256-bit-secret",
                "supersecret", "key", "test", "default", "qwerty", "letmein", "s3cr3t", "mysecret", "token", "private"]
HMAC = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


@dataclass
class Finding:
    severity: str
    code: str
    message: str

    def as_dict(self):
        return self.__dict__.copy()


class JWTError(ValueError):
    pass


def b64d(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode(token: str) -> tuple[dict, dict, bytes, str]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise JWTError("a JWT has exactly 3 dot-separated parts")
    try:
        header = json.loads(b64d(parts[0]))
        payload = json.loads(b64d(parts[1]))
        sig = b64d(parts[2]) if parts[2] else b""
    except Exception as e:  # noqa: BLE001
        raise JWTError(f"cannot decode token: {e}") from e
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JWTError("header and payload must be JSON objects")
    return header, payload, sig, f"{parts[0]}.{parts[1]}"


def crack_hmac(alg: str, signing_input: str, sig: bytes, wordlist: list[str]) -> str | None:
    h = HMAC.get(alg)
    if not h:
        return None
    for w in wordlist:
        if hmac.compare_digest(hmac.new(w.encode(), signing_input.encode(), h).digest(), sig):
            return w
    return None


def audit(token: str, now: float | None = None, wordlist: list[str] | None = None, expected_aud: str | None = None) -> list[Finding]:
    header, payload, sig, signing_input = decode(token)
    now = time.time() if now is None else now
    out: list[Finding] = []
    alg = str(header.get("alg", ""))

    if alg.lower() == "none" or not sig:
        out.append(Finding("critical", "ALG_NONE", "unsigned token (alg none or empty signature): accept only if the server rejects it"))
    if alg in HMAC:
        secret = crack_hmac(alg, signing_input, sig, (wordlist or []) + WEAK_SECRETS)
        if secret is not None:
            out.append(Finding("critical", "WEAK_SECRET", f"HMAC secret is guessable from a small wordlist ('{secret}')"))
        out.append(Finding("info", "HMAC_ALG", f"{alg} uses a shared secret: check for algorithm confusion if the server also supports RSA/EC keys"))
    if alg.startswith(("RS", "ES", "PS")) and header.get("typ") is None:
        out.append(Finding("info", "NO_TYP", "no typ header (RFC 8725 recommends explicit typing)"))
    for k in ("jku", "x5u"):
        if k in header:
            out.append(Finding("high", f"{k.upper()}_HEADER", f"'{k}' points to a remote key set ({header[k]}): verify servers pin an allowlist, else key injection is possible"))
    for k in ("jwk", "x5c"):
        if k in header:
            out.append(Finding("high", f"{k.upper()}_EMBEDDED", f"'{k}' embeds a key in the token: servers must never trust it"))
    if "kid" in header:
        kid = str(header["kid"])
        if any(c in kid for c in ("/", "\\", "'", '"', ";", "|", "..", "\0")):
            out.append(Finding("high", "KID_INJECTION", "kid contains path or injection characters (path traversal or SQLi in key lookup)"))

    exp, nbf, iat = payload.get("exp"), payload.get("nbf"), payload.get("iat")
    if exp is None:
        out.append(Finding("medium", "NO_EXP", "no exp claim: token never expires"))
    elif not isinstance(exp, (int, float)):
        out.append(Finding("medium", "BAD_EXP", "exp is not a number"))
    elif exp < now:
        out.append(Finding("info", "EXPIRED", f"token expired {int(now - exp)}s ago"))
    elif isinstance(iat, (int, float)) and exp - iat > 30 * 86400:
        out.append(Finding("medium", "LONG_LIFETIME", f"lifetime is {int((exp - iat) / 86400)} days"))
    if isinstance(nbf, (int, float)) and nbf > now:
        out.append(Finding("info", "NOT_YET_VALID", "nbf is in the future"))
    if "iss" not in payload:
        out.append(Finding("low", "NO_ISS", "no iss claim"))
    if "aud" not in payload:
        out.append(Finding("low", "NO_AUD", "no aud claim (token could be replayed across services)"))
    elif expected_aud:
        aud = payload["aud"] if isinstance(payload["aud"], list) else [payload["aud"]]
        if expected_aud not in aud:
            out.append(Finding("high", "AUD_MISMATCH", f"aud does not contain '{expected_aud}'"))
    if any(k in payload for k in ("password", "pwd", "secret", "ssn", "credit_card")):
        out.append(Finding("high", "SENSITIVE_CLAIM", "payload carries sensitive data; JWT payloads are only encoded, not encrypted"))
    if payload.get("admin") is True or payload.get("role") in ("admin", "root"):
        out.append(Finding("info", "PRIVILEGED", "token asserts admin/root: verify claims are server-controlled"))
    return out


def human_times(payload: dict) -> dict[str, str]:
    out = {}
    for k in ("iat", "nbf", "exp"):
        v = payload.get(k)
        if isinstance(v, (int, float)):
            out[k] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(v))
    return out


def forge_unsigned(payload: dict) -> str:
    """Build an alg=none token, strictly for testing that YOUR OWN server rejects it."""
    return f"{b64e(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())}.{b64e(json.dumps(payload).encode())}."
