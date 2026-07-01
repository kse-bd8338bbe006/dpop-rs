# dpop-rs

A small, readable **DPoP-protected resource server** (RFC 9449) for the API Security
course - **Lecture 8: sender-constrained tokens**. It is the server side of the DPoP
practice: students point their own client at it and watch a stolen token become
useless without the key.

The client side lives in
[`oauth-advanced-grants`](https://github.com/kse-bd8338bbe006/oauth-advanced-grants)
(`dpop_demo.py`).

## What it enforces

`GET|POST /api/resource` requires two things on every request:

```http
Authorization: DPoP <access-token>     # Keycloak's JWT, DPoP scheme (not Bearer)
DPoP: <proof-jwt>                       # a fresh proof signed by the client's key
```

and runs the four checks the lecture describes, returning `401` with the **name of
the failed check** so it is obvious what a resource server actually does:

1. **token** - the access token is a valid Keycloak-signed JWT and is **DPoP-bound**
   (`cnf.jkt` present; a plain bearer token is rejected).
2. **signature / key-mismatch** - the proof signature verifies with the `jwk` in its
   header, and `SHA-256(jwk) == cnf.jkt` (the caller holds the bound key).
3. **htm / htu** - the proof's method and URL match this request.
4. **ath / jti / iat** - `ath` matches this token, the `jti` is fresh (no replay),
   and `iat` is recent.

`GET /api/health` returns `{"status":"UP"}` for the Kubernetes probes.

## Run locally

```bash
pip install -r requirements.txt
python app.py            # listens on :8000
# health
curl -s localhost:8000/api/health
```

Config via environment:

| var | default |
|-----|---------|
| `KEYCLOAK_ISSUER_URI` | `https://keycloak.192.168.50.10.nip.io/realms/api-security` |
| `PUBLIC_BASE_URL` | `https://dpop-rs.192.168.50.10.nip.io` (used to check `htu`) |
| `DPOP_IAT_SKEW_SECONDS` | `300` (tolerates lab VM clock drift) |
| `PORT` | `8000` |

## In the lab

Built by CI to `ghcr.io/kse-bd8338bbe006/dpop-rs:<sha>` (multi-arch) and deployed by
`kse-labs-deployment` (ArgoCD) at `https://dpop-rs.192.168.50.10.nip.io`.

## Notes

- Verifying the **access token** uses PyJWT + the Keycloak JWKS. Verifying the **DPoP
  proof** (ES256 / P-256) is done by hand so every step is visible - this is teaching
  code, not a framework showcase.
- `jti` replay state is in-memory (single replica); fine for a lab, not for production.
