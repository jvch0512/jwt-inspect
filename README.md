# jwt-inspect

Decode and audit JSON Web Tokens **offline**. Signatures are never verified: this is an analysis tool for pentesters, developers and incident responders, not an authentication library.

## What it flags

| Code | Severity | Meaning |
|------|----------|---------|
| `ALG_NONE` | critical | unsigned token |
| `WEAK_SECRET` | critical | HS256/384/512 secret found in a built-in or custom wordlist |
| `JKU_HEADER`, `X5U_HEADER` | high | token points to a remote key set (key injection risk) |
| `JWK_EMBEDDED`, `X5C_EMBEDDED` | high | token embeds its own key |
| `KID_INJECTION` | high | path traversal or SQLi characters in `kid` |
| `AUD_MISMATCH` | high | `aud` does not include the audience you expect |
| `SENSITIVE_CLAIM` | high | password, SSN, card number in an unencrypted payload |
| `NO_EXP`, `LONG_LIFETIME` | medium | never expires, or lifetime over 30 days |
| `NO_ISS`, `NO_AUD` | low | missing issuer or audience |
| `HMAC_ALG`, `EXPIRED`, `NOT_YET_VALID`, `PRIVILEGED` | info | context for the analyst |

References: RFC 7519, RFC 8725 (JWT best current practices), OWASP JWT cheat sheet.

## Usage

```bash
pip install -e .
jwt-inspect "$TOKEN"
echo "$TOKEN" | jwt-inspect - --aud my-api --format json
jwt-inspect "$TOKEN" --wordlist rockyou-top1000.txt --fail-on high
```

`forge_unsigned()` in `jwt_inspect.core` builds an `alg: none` token so you can test that **your own** server rejects it.

## Safety

Do not paste production tokens into online decoders: this tool runs locally and makes no network calls. Test fixtures build tokens at runtime, so the repo holds no real credentials.

## Development

```bash
pip install -e .[dev] && pytest -q
```

MIT licensed.
