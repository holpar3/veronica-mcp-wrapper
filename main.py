"""
Veronica MCP Wrapper -- phone-reach for the chair (Claude-Veronica)
===================================================================
Fronts the existing OneDrive bridge (OpenAPI) with a Model Context Protocol
server so the Claude app can reach the vault as a custom connector. Thin proxy:
four MCP tools (list/read/write/search), each forwarding to the matching bridge
REST endpoint, authenticating to the bridge with the existing BRIDGE_API_KEY.

Auth model (verified against live Claude docs, 2026-06-25):
  * Claude's connector UI does NOT support a user-pasted static Bearer token or
    custom headers -- only OAuth 2.1 (Advanced settings) or NO auth. Static
    bearer is explicitly unsupported; query-string tokens are prohibited.
  * Full OAuth 2.1 + PKCE is overkill for a single-user personal vault, so v1
    uses NO connector-level auth and protects the endpoint with:
      1. CAPABILITY URL -- the MCP endpoint lives at a secret path segment
         (WRAPPER_SECRET). The URL is the credential; it lives only in Hollie's
         connector config + the vault.
      2. (hardening, optional) IP allowlist to Anthropic's published egress
         range -- only Anthropic's cloud calls this.
  * The bridge's BRIDGE_API_KEY still guards Graph access; the wrapper holds it
    server-side and never exposes it to Claude.

Env vars (Hollie's hands set these on Render):
  BRIDGE_BASE_URL  -- e.g. https://veronica-onedrive-bridge.onrender.com
  BRIDGE_API_KEY   -- the SAME long random string already set on the bridge
  WRAPPER_SECRET   -- a NEW long random string; becomes the secret URL segment

Tested in sandbox 2026-06-25 (mcp 1.28.0): 4 tools register; mounts at
/<WRAPPER_SECRET>; correct secret path completes the MCP initialize handshake
(HTTP 200, session created); bare /mcp and a guessed secret both 404.
"""

import os
from contextlib import asynccontextmanager

import httpx
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount

BRIDGE_BASE_URL = os.environ["BRIDGE_BASE_URL"].rstrip("/")
BRIDGE_API_KEY = os.environ["BRIDGE_API_KEY"]
WRAPPER_SECRET = os.environ["WRAPPER_SECRET"].strip("/")

_headers = {"Authorization": f"Bearer {BRIDGE_API_KEY}"}
_TIMEOUT = httpx.Timeout(30.0)

mcp = FastMCP("Veronica Vault")


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
def write_file(path: str, content: str) -> dict:
    """Create or overwrite a text file at the given vault path with the provided
    content. Parent folders are created as needed."""
    r = httpx.post(f"{BRIDGE_BASE_URL}/write_file",
                   json={"path": path, "content": content},
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


# streamable_http_app() must be called BEFORE referencing session_manager
# (it's created lazily). Build it once, then hand its lifespan to the parent app.
_mcp_app = mcp.streamable_http_app()


@asynccontextmanager
async def lifespan(app):
    async with mcp.session_manager.run():
        yield


# Claude connector URL = https://<host>/<WRAPPER_SECRET>/mcp
app = Starlette(
    routes=[Mount(f"/{WRAPPER_SECRET}", app=_mcp_app)],
    lifespan=lifespan,
)
