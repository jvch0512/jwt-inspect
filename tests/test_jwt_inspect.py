import hashlib
import hmac
import json

import pytest

from jwt_inspect.cli import main
from jwt_inspect.core import JWTError, audit, b64e, decode, forge_unsigned, human_times

NOW = 1_800_000_000


def make_token(payload, secret="k" * 32, header=None, alg="HS256"):
    h = header or {"alg": alg, "typ": "JWT"}
    si = b64e(json.dumps(h).encode()) + "." + b64e(json.dumps(payload).encode())
    sig = hmac.new(secret.encode(), si.encode(), hashlib.sha256).digest()
    return si + "." + b64e(sig)


GOOD = {"iss": "me", "aud": "api", "iat": NOW - 60, "exp": NOW + 600, "sub": "1"}


def codes(token, **kw):
    return {f.code for f in audit(token, now=NOW, **kw)}


def test_decode_roundtrip():
    h, p, sig, si = decode(make_token(GOOD))
    assert h["alg"] == "HS256" and p["sub"] == "1" and sig and si.count(".") == 1


@pytest.mark.parametrize("bad", ["abc", "a.b", "a.b.c.d", "!!!.???.***"])
def test_malformed_tokens_raise(bad):
    with pytest.raises(JWTError):
        decode(bad)


def test_clean_token_has_no_serious_findings():
    assert codes(make_token(GOOD)) <= {"HMAC_ALG"}


def test_weak_secret_is_cracked():
    assert "WEAK_SECRET" in codes(make_token(GOOD, secret="secret"))


def test_custom_wordlist():
    assert "WEAK_SECRET" in codes(make_token(GOOD, secret="hunter42"), wordlist=["hunter42"])
    assert "WEAK_SECRET" not in codes(make_token(GOOD, secret="hunter42"))


def test_alg_none_forged_token():
    assert "ALG_NONE" in codes(forge_unsigned(GOOD))


def test_time_claims():
    assert "NO_EXP" in codes(make_token({"iss": "x", "aud": "y"}))
    assert "EXPIRED" in codes(make_token({**GOOD, "exp": NOW - 5}))
    assert "LONG_LIFETIME" in codes(make_token({**GOOD, "iat": NOW, "exp": NOW + 90 * 86400}))
    assert "NOT_YET_VALID" in codes(make_token({**GOOD, "nbf": NOW + 999}))


def test_missing_and_mismatched_claims():
    assert {"NO_ISS", "NO_AUD"} <= codes(make_token({"exp": NOW + 10}))
    assert "AUD_MISMATCH" in codes(make_token(GOOD), expected_aud="other")
    assert "AUD_MISMATCH" not in codes(make_token(GOOD), expected_aud="api")


def test_dangerous_headers():
    t = make_token(GOOD, header={"alg": "HS256", "jku": "https://evil.example/jwks.json", "kid": "../../dev/null"})
    assert {"JKU_HEADER", "KID_INJECTION"} <= codes(t)
    assert "JWK_EMBEDDED" in codes(make_token(GOOD, header={"alg": "HS256", "jwk": {"kty": "oct"}}))


def test_sensitive_and_privileged_claims():
    c = codes(make_token({**GOOD, "password": "x", "admin": True}))
    assert {"SENSITIVE_CLAIM", "PRIVILEGED"} <= c


def test_human_times():
    assert human_times({"exp": 0})["exp"].startswith("1970-01-01")


def test_cli_json_and_exit_codes(capsys):
    t = make_token(GOOD, secret="secret")
    assert main([t, "--format", "json"]) == 2
    data = json.loads(capsys.readouterr().out)
    assert data["payload"]["sub"] == "1" and any(f["code"] == "WEAK_SECRET" for f in data["findings"])
    assert main(["garbage"]) == 1


def test_cli_stdin(monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(make_token(GOOD) + "\n"))
    assert main(["-", "--fail-on", "critical"]) == 0
