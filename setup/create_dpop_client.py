#!/usr/bin/env python3
"""
Create the `dpop-practice` client in the lab Keycloak (api-security realm).

This is the scripted equivalent of the manual UI steps in the Lecture 8 practice:
a confidential client with a service account and DPoP-bound access tokens
*required*. Idempotent - safe to run more than once.

Usage:
    python create_dpop_client.py

Environment overrides (defaults target the course lab):
    KC_BASE      https://keycloak.192.168.50.10.nip.io
    REALM        api-security
    ADMIN_USER   admin
    ADMIN_PASS   admin
    CLIENT_ID    dpop-practice
    CLIENT_SECRET dpop-practice-secret-lab-2026
"""
import os
import sys

import requests

requests.packages.urllib3.disable_warnings()  # lab uses a self-signed internal CA

KC = os.environ.get("KC_BASE", "https://keycloak.192.168.50.10.nip.io")
REALM = os.environ.get("REALM", "api-security")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")
CLIENT_ID = os.environ.get("CLIENT_ID", "dpop-practice")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "dpop-practice-secret-lab-2026")

REPRESENTATION = {
    "clientId": CLIENT_ID,
    "name": "DPoP practice client (Lecture 8)",
    "enabled": True,
    "publicClient": False,
    "standardFlowEnabled": True,
    "directAccessGrantsEnabled": True,
    "serviceAccountsEnabled": True,
    "secret": CLIENT_SECRET,
    "redirectUris": ["http://localhost:8080/*", "http://127.0.0.1/*"],
    "webOrigins": ["http://localhost:8080"],
    # This is the switch that makes DPoP REQUIRED for this client.
    "attributes": {"dpop.bound.access.tokens": "true"},
    "protocol": "openid-connect",
}


def admin_token(s):
    r = s.post(f"{KC}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": ADMIN_USER, "password": ADMIN_PASS,
    })
    r.raise_for_status()
    return r.json()["access_token"]


def main():
    s = requests.Session()
    s.verify = False
    try:
        token = admin_token(s)
    except Exception as e:  # noqa: BLE001
        print(f"Cannot get an admin token from {KC}: {e}")
        sys.exit(1)
    h = {"Authorization": f"Bearer {token}"}
    base = f"{KC}/admin/realms/{REALM}/clients"

    existing = s.get(base, headers=h, params={"clientId": CLIENT_ID}).json()
    if existing:
        cid = existing[0]["id"]
        s.put(f"{base}/{cid}", headers=h, json={**existing[0], **REPRESENTATION})
        print(f"updated existing client '{CLIENT_ID}' ({cid})")
    else:
        r = s.post(base, headers=h, json=REPRESENTATION)
        if r.status_code not in (201, 204):
            print(f"failed to create client: HTTP {r.status_code} {r.text}")
            sys.exit(1)
        print(f"created client '{CLIENT_ID}'")

    print(f"  confidential, service account, DPoP required "
          f"(dpop.bound.access.tokens=true), secret='{CLIENT_SECRET}'")
    print(f"  realm: {REALM}  at {KC}")


if __name__ == "__main__":
    main()
