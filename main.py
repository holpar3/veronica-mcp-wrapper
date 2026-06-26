"""
Veronica MCP Wrapper v2 -- OAuth layer (read-only phone connector)
==================================================================
Phase 3b. Fronts the existing OneDrive bridge with a Model Context Protocol
server the Claude app can register as a custom connector. v1 (secret-URL, no
auth) deployed clean but the Claude *Connect* button refuses a no-auth public
server -- it requires OAuth 2.1. This version adds that, the right way:

  * Built on standalone FastMCP v2 (pkg `fastmcp`, gofastmcp.com) -- NOT the
    base `mcp` SDK's FastMCP. Different package. The auth providers live here.
  * GoogleProvider = FastMCP's OAuth proxy pointed at Google. Google does the
    actual "is this Hollie" login; the proxy presents Claude a standards-clean
    OAuth 2.1 + PKCE face and never hands Claude the upstream Google token
    (token-factory pattern -- Claude only ever gets a FastMCP-issued JWT).

Posture (Hollie-approved, 25 Jun): swap the lock, don't widen the door.
  1. READ-ONLY. write_file is dropped. Worst case at this door = someone reads
     journals, never writes. Writes stay laptop-only (the Mac MCP).
  2. GOOGLE-DELEGATED login -- the crypto-adjacent parts (PKCE, token issuance,
     redirect matching) come from FastMCP's vetted proxy, not hand-rolled.
  3. BATTALION identity gate -- enforced at the Google layer: the OAuth client
     lives under the Battalion account in "Testing" publishing status with ONLY
     dinosauronesiebattalion@gmail.com as a test user, so Google blocks every
     other account at consent. (In-code email allowlist is a future hardening
     once we can observe the real token claims live; left out of v1 to avoid a
     fail-closed lockout on an unverified assumption.)

Blast radius, unchanged by OAuth: the vault rides Hollie's PERSONAL OneDrive,
and the bridge holds Files.ReadWrite to that whole drive. OAuth neither widens
nor narrows that -- it's a different front-door lock on the same bridge.
Read-only here is what actually shrinks the worst case at THIS door.

Verified live against fastmcp 3.4.2 (2026-06-26) + sandbox-tested:
  - module imports clean with full OAuth config;
  - /.well-known/oauth-authorization-server + .../oauth-protected-resource/mcp
    serve correct metadata;
  - unauth POST /mcp -> 401 with WWW-Authenticate carrying resource_metadata
    (the exact discovery header the no-auth wrapper could not produce -> this
    is what makes Claude's Connect button start the flow instead of dying);
  - only list_files/read_file/search_files register (no write_file).

Env vars (Hollie's hands set these on Render):
  BRIDGE_BASE_URL          existing -- the OneDrive bridge URL (GET /health -> ok)
  BRIDGE_API_KEY           existing -- same key already on the bridge
  PUBLIC_URL               this wrapper's own public https URL on Render
  GOOGLE_CLIENT_ID         from the Battalion Google OAuth client (Web app)
  GOOGLE_CLIENT_SECRET     "
  JWT_SIGNING_KEY          a NEW long random string (>=32 chars). Fixed across
                           restarts so issued tokens stay valid through redeploys.
  STORAGE_ENCRYPTION_KEY   a Fernet key: python -c "from cryptography.fernet
                           import Fernet;print(Fernet.generate_key().decode())"
  STORAGE_DIR              path on the mounted persistent disk, e.g. /data/oauth
"""

import os
import httpx
from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider
from cryptography.fernet import Fernet
from key_value.aio.stores.disk import DiskStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

# --- existing bridge wiring (held server-side; never exposed to Claude) ---
BRIDGE_BASE_URL = os.environ["BRIDGE_BASE_URL"].rstrip("/")
BRIDGE_API_KEY = os.environ["BRIDGE_API_KEY"]
_headers = {"Authorization": f"Bearer {BRIDGE_API_KEY}"}
_TIMEOUT = httpx.Timeout(30.0)

# --- OAuth / public config ---
PUBLIC_URL = os.environ["PUBLIC_URL"].rstrip("/")
GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
JWT_SIGNING_KEY = os.environ["JWT_SIGNING_KEY"]
STORAGE_ENCRYPTION_KEY = os.environ["STORAGE_ENCRYPTION_KEY"]
STORAGE_DIR = os.environ.get("STORAGE_DIR", "/data/oauth")

# Persistent, encrypted storage for OAuth client registrations + upstream tokens.
# This is the fix for the widespread "connects, then drops, can't reconnect
# without removing the connector" bug: on Linux, FastMCP defaults to in-memory
# storage + ephemeral keys, so every restart invalidates everything. A disk
# store on a mounted Render disk + a fixed JWT_SIGNING_KEY makes it survive
# redeploys and recycles. Fernet encrypts the upstream tokens at rest.
_storage = FernetEncryptionWrapper(
    key_value=DiskStore(directory=STORAGE_DIR),
    fernet=Fernet(STORAGE_ENCRYPTION_KEY),
)

auth = GoogleProvider(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    base_url=PUBLIC_URL,
    required_scopes=["openid", "https://www.googleapis.com/auth/userinfo.email"],
    # Exact-match allowlist for the client callback. claude.ai is the live host;
    # .com included as the documented variant. Defense-in-depth -- the real
    # identity gate is Google's test-user list.
    allowed_client_redirect_uris=[
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
    ],
    client_storage=_storage,
    jwt_signing_key=JWT_SIGNING_KEY,
    # One client (the Claude app). Disabling CIMD keeps client_ids as UUIDs
    # (filesystem-safe for the disk store) and shrinks the attack surface;
    # also sidesteps the CIMD+disk path bug (fastmcp #3574).
    enable_cimd=False,
    # Ask Google for a refresh token so sessions renew without a full re-login.
    # (In Google "Testing" status these refresh tokens still expire ~7 days, so
    # expect roughly weekly re-consent -- that's Google policy, not a fault.)
    extra_authorize_params={"access_type": "offline", "prompt": "consent"},
    # Decouple the FastMCP token lifetime from Google's short access-token TTL;
    # the proxy transparently refreshes upstream underneath.
    fastmcp_access_token_expiry_seconds=60 * 60 * 24 * 7,  # 7 days
    require_authorization_consent=True,  # confused-deputy defense; keep on
)

mcp = FastMCP("Veronica Vault", auth=auth)


@mcp.tool()
def list_files(path: str = "") -> dict:
    """List files and folders at a vault path. Leave path empty for the vault root.
    Returns each item's name, whether it is a file or folder, and its size in bytes."""
    r = httpx.get(f"{BRIDGE_BASE_URL}/list_files", params={"path": path},
                  headers=_headers, timeout=_TIMEOUT)
    r.raise_for_status()
    return r.json()


@mcp.tool()
def read_file(path: str) -> dict:
    """Read the UTF-8 text contents of a file at the given vault path,
    for example 'Veronica/Read Me First.md'."""
    r = httpx.get(f"{BRIDGE_BASE_URL}/read_file", params={"path": path},
                  headers=_headers, timeout=_TIMEOUT)
    r.raise_for_status()
    return r.json()


@mcp.tool()
def search_files(query: str) -> dict:
    """Search the whole vault for files whose name or contents match the query.
    Returns matching file names and their folder paths."""
    r = httpx.get(f"{BRIDGE_BASE_URL}/search_files", params={"query": query},
                  headers=_headers, timeout=_TIMEOUT)
    r.raise_for_status()
    return r.json()


# write_file intentionally omitted for v1 (read-only phone connector).
# To restore write later, re-add the tool here and redeploy.

# ASGI app for uvicorn (mounts /mcp + all OAuth routes automatically).
# Connector URL = https://<host>/mcp  (no secret path segment -- OAuth is the gate now).
app = mcp.http_app()
