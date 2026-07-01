"""
DPoP-protected resource server (RFC 9449) for the API Security course - Lecture 8.

It exposes a protected endpoint that a client may call only with:
  - a valid Keycloak access token, presented as   Authorization: DPoP <access-token>
  - a fresh DPoP proof in the                      DPoP: <proof-jwt>   header

On every request it enforces the four checks the lecture describes, and it names
the one that fails so students can see exactly what a resource server does:

  1. the access token is a valid Keycloak-signed JWT and is DPoP-bound (has cnf.jkt)
  2. the DPoP proof signature verifies with the jwk in its header,
     and SHA-256(jwk) == cnf.jkt      -> the caller holds the bound key
  3. htm / htu in the proof match this request's method and URL
  4. ath == base64url(SHA-256(access token)); jti is fresh; iat is recent

It is deliberately dependency-light and readable - it is teaching material, not a
framework showcase. Verifying the access token uses PyJWT + the Keycloak JWKS;
verifying the DPoP proof (ES256/EdDSA) is done by hand so every step is visible.
"""
import base64
import hashlib
import json
import os
import time

import jwt  # PyJWT
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from flask import Flask, jsonify, request

# --- config (env-overridable; defaults target the course lab) ----------------
ISSUER = os.environ.get(
    "KEYCLOAK_ISSUER_URI",
    "https://keycloak.192.168.50.10.nip.io/realms/api-security",
)
JWKS_URI = f"{ISSUER}/protocol/openid-connect/certs"
# The external URL clients use to reach us; htu in the proof must match this.
# Behind the ingress we also reconstruct it from forwarded headers.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL", "https://dpop-rs.192.168.50.10.nip.io")
IAT_SKEW = int(os.environ.get("DPOP_IAT_SKEW_SECONDS", "300"))  # tolerate lab clock drift
# The lab uses a self-signed internal CA. Point OAUTH_CA_BUNDLE at a CA file to verify.
VERIFY = os.environ.get("OAUTH_CA_BUNDLE", False)

app = Flask(__name__)
_seen_jti: dict[str, float] = {}       # jti -> first-seen epoch (single replica: fine)
_jwks_keys: dict[str, object] = {}     # kid -> verification key
_jwks_ts = 0.0


def signing_key(kid: str):
    """Return the Keycloak signing key for kid, refreshing the JWKS cache as needed."""
    global _jwks_ts
    if kid not in _jwks_keys or (time.time() - _jwks_ts) > 300:
        r = requests.get(JWKS_URI, verify=VERIFY, timeout=8)
        r.raise_for_status()
        fresh = {}
        for k in r.json().get("keys", []):
            cls = {"RSA": jwt.algorithms.RSAAlgorithm,
                   "EC": jwt.algorithms.ECAlgorithm}.get(k.get("kty"))
            if cls and k.get("kid"):
                try:
                    fresh[k["kid"]] = cls.from_jwk(json.dumps(k))
                except Exception:
                    pass
        _jwks_keys.clear()
        _jwks_keys.update(fresh)
        _jwks_ts = time.time()
    return _jwks_keys.get(kid)


# --- helpers -----------------------------------------------------------------
def b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 thumbprint for an EC key (the only curve type we accept here)."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"), sort_keys=True,
    ).encode()
    return b64url(hashlib.sha256(canonical).digest())


def verify_es256(signing_input: bytes, sig_b64: str, jwk: dict) -> bool:
    """Verify a P-256 / ES256 JOSE signature (raw r||s) with the proof's public jwk."""
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        return False
    x = int.from_bytes(b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(b64url_decode(jwk["y"]), "big")
    pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    raw = b64url_decode(sig_b64)
    if len(raw) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        from cryptography.hazmat.primitives import hashes
        pub.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def expected_htu() -> str:
    """The absolute request URL the client should have signed into htu.

    Behind the nginx ingress TLS is terminated, so rebuild the external URL from
    forwarded headers; fall back to PUBLIC_BASE_URL + path.
    """
    proto = request.headers.get("X-Forwarded-Proto")
    host = request.headers.get("X-Forwarded-Host") or request.host
    if proto and host:
        return f"{proto}://{host}{request.path}"
    return f"{PUBLIC_BASE_URL.rstrip('/')}{request.path}"


class DPoPError(Exception):
    def __init__(self, check: str, detail: str):
        self.check, self.detail = check, detail


def _evict_old_jti(now: float) -> None:
    for k, seen in list(_seen_jti.items()):
        if now - seen > IAT_SKEW:
            _seen_jti.pop(k, None)


def validate(req) -> dict:
    """Run the four checks. Returns the verified token claims or raises DPoPError."""
    now = time.time()

    # --- Check 1: access token present as DPoP, valid, and DPoP-bound ---
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("DPoP "):
        raise DPoPError("scheme", "Authorization header must use the DPoP scheme, not Bearer")
    access_token = auth[len("DPoP "):].strip()
    try:
        kid = jwt.get_unverified_header(access_token).get("kid")
        key = signing_key(kid)
        if key is None:
            raise ValueError(f"unknown signing key kid={kid}")
        claims = jwt.decode(access_token, key, algorithms=["RS256", "ES256", "PS256"],
                            issuer=ISSUER, options={"verify_aud": False})
    except Exception as e:
        raise DPoPError("token", f"access token is not a valid {ISSUER} JWT: {e}")
    cnf_jkt = (claims.get("cnf") or {}).get("jkt")
    if not cnf_jkt:
        raise DPoPError("binding", "access token has no cnf.jkt - it is a plain bearer token")

    # --- parse the DPoP proof ---
    proof = req.headers.get("DPoP")
    if not proof:
        raise DPoPError("proof", "missing DPoP proof header")
    try:
        h_b64, p_b64, sig_b64 = proof.split(".")
        header = json.loads(b64url_decode(h_b64))
        payload = json.loads(b64url_decode(p_b64))
    except Exception:
        raise DPoPError("proof", "DPoP proof is not a well-formed JWT")
    if header.get("typ") != "dpop+jwt":
        raise DPoPError("proof", "DPoP proof typ must be dpop+jwt")
    jwk = header.get("jwk")
    if not jwk:
        raise DPoPError("proof", "DPoP proof header must carry the public jwk")

    # --- Check 2: signature valid AND thumbprint(jwk) == cnf.jkt ---
    if not verify_es256(f"{h_b64}.{p_b64}".encode(), sig_b64, jwk):
        raise DPoPError("signature", "DPoP proof signature does not verify with its jwk")
    if jwk_thumbprint(jwk) != cnf_jkt:
        raise DPoPError("key-mismatch",
                        "thumbprint(jwk) != cnf.jkt - proof key is not the bound key")

    # --- Check 3: htm / htu match this request ---
    if payload.get("htm") != req.method:
        raise DPoPError("htm", f"proof htm={payload.get('htm')} != request method {req.method}")
    want = expected_htu()
    if (payload.get("htu") or "").rstrip("/") != want.rstrip("/"):
        raise DPoPError("htu", f"proof htu={payload.get('htu')} != request URL {want}")

    # --- Check 4: ath binds the proof to THIS token; jti fresh; iat recent ---
    ath = b64url(hashlib.sha256(access_token.encode()).digest())
    if payload.get("ath") != ath:
        raise DPoPError("ath", "proof ath does not match SHA-256 of the access token")
    iat = payload.get("iat")
    if not isinstance(iat, (int, float)) or abs(now - iat) > IAT_SKEW:
        raise DPoPError("iat", "proof iat is missing or outside the acceptance window")
    jti = payload.get("jti")
    if not jti:
        raise DPoPError("jti", "proof has no jti")
    _evict_old_jti(now)
    if jti in _seen_jti:
        raise DPoPError("replay", "this DPoP proof (jti) was already used")
    _seen_jti[jti] = now

    return {"sub": claims.get("sub"), "client_id": claims.get("client_id") or claims.get("azp"),
            "jkt": cnf_jkt, "scope": claims.get("scope")}


# --- routes ------------------------------------------------------------------
@app.get("/api/health")
def health():
    return jsonify(status="UP")


@app.route("/api/resource", methods=["GET", "POST"])
def resource():
    try:
        who = validate(request)
    except DPoPError as e:
        return jsonify(error="invalid_dpop", failed_check=e.check, detail=e.detail), 401
    return jsonify(
        message="DPoP proof accepted - you hold the key this token is bound to.",
        method=request.method,
        caller=who,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
