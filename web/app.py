"""
Dead Drop Web UI — API server.

Serves the single-page app and provides crypto endpoints
backed by the dead_drop library.

Author: Ava Shakil
Date: 2026-02-28
"""

import json
import sys
import os
import base64
from pathlib import Path

from aiohttp import web

# Ensure dead_drop is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dead_drop


# ---------------------------------------------------------------------------
# API handlers
# ---------------------------------------------------------------------------

async def api_create(request: web.Request) -> web.Response:
    """
    POST /api/create
    Body JSON: { payload: str, n: int, k: int, payload_b64?: str }
    
    If payload_b64 is provided, it's decoded as raw bytes (file upload).
    Otherwise payload is treated as UTF-8 text.
    
    Returns: { ciphertext_hex, shares, drop_id, n, k }
    """
    try:
        data = await request.json()
    except Exception:
        return _err("Invalid JSON body", 400)

    n = data.get("n")
    k = data.get("k")
    payload_text = data.get("payload", "")
    payload_b64 = data.get("payload_b64")

    if n is None or k is None:
        return _err("Missing n or k", 400)

    try:
        n, k = int(n), int(k)
    except (ValueError, TypeError):
        return _err("n and k must be integers", 400)

    if k < 2:
        return _err("Threshold k must be >= 2", 400)
    if n < k:
        return _err("Total shares n must be >= threshold k", 400)
    if n > 255:
        return _err("n must be <= 255", 400)

    # Resolve payload bytes
    if payload_b64:
        try:
            payload_bytes = base64.b64decode(payload_b64)
        except Exception:
            return _err("Invalid base64 payload", 400)
    elif payload_text:
        payload_bytes = payload_text.encode("utf-8")
    else:
        return _err("No payload provided", 400)

    if len(payload_bytes) == 0:
        return _err("Payload must not be empty", 400)

    try:
        drop, shares = dead_drop.create(payload_bytes, n, k)
    except Exception as exc:
        return _err(f"Create failed: {exc}", 500)

    return web.json_response({
        "ok": True,
        "drop_id": drop.drop_id,
        "n": n,
        "k": k,
        "ciphertext_hex": drop.ciphertext.hex(),
        "ciphertext_size": len(drop.ciphertext),
        "payload_size": len(payload_bytes),
        "shares": shares,
    })


async def api_recover(request: web.Request) -> web.Response:
    """
    POST /api/recover
    Body JSON: { shares: [str, ...], ciphertext_hex: str, k: int }
    
    Returns: { payload: str, payload_b64: str, payload_size: int }
    """
    try:
        data = await request.json()
    except Exception:
        return _err("Invalid JSON body", 400)

    shares = data.get("shares", [])
    ct_hex = data.get("ciphertext_hex", "")
    k = data.get("k")

    if not shares or not ct_hex or k is None:
        return _err("Missing shares, ciphertext_hex, or k", 400)

    try:
        k = int(k)
    except (ValueError, TypeError):
        return _err("k must be an integer", 400)

    try:
        ciphertext = bytes.fromhex(ct_hex)
    except ValueError:
        return _err("Invalid ciphertext hex", 400)

    try:
        plaintext = dead_drop.recover(shares, ciphertext, k)
    except Exception as exc:
        return _err(f"Recovery failed: {exc}", 400)

    # Try to decode as UTF-8 text; fall back to base64
    try:
        payload_text = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        payload_text = None

    return web.json_response({
        "ok": True,
        "payload": payload_text,
        "payload_b64": base64.b64encode(plaintext).decode("ascii"),
        "payload_size": len(plaintext),
    })


async def api_verify(request: web.Request) -> web.Response:
    """
    POST /api/verify
    Body JSON: { shares: [str, ...] }
    
    Returns verification result dict.
    """
    try:
        data = await request.json()
    except Exception:
        return _err("Invalid JSON body", 400)

    shares = data.get("shares", [])
    if not shares:
        return _err("No shares provided", 400)

    result = dead_drop.verify_shares(shares)
    result["ok"] = True
    return web.json_response(result)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _err(msg: str, status: int = 400) -> web.Response:
    return web.json_response({"ok": False, "error": msg}, status=status)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> web.Application:
    app = web.Application(client_max_size=10 * 1024 * 1024)  # 10 MB uploads

    # API routes
    app.router.add_post("/api/create", api_create)
    app.router.add_post("/api/recover", api_recover)
    app.router.add_post("/api/verify", api_verify)

    # Serve index.html at root
    web_dir = Path(__file__).resolve().parent
    index_path = web_dir / "index.html"

    async def serve_index(request):
        return web.FileResponse(index_path)

    app.router.add_get("/", serve_index)

    # Serve any other static files from web/
    app.router.add_static("/static/", web_dir, show_index=False)

    return app


if __name__ == "__main__":
    app = create_app()
    print("🔮 Dead Drop Web UI — http://localhost:8787")
    web.run_app(app, host="0.0.0.0", port=8787)
