"""
Miracle Connector - Render deployment
Receives DBF data pushed from Windows server, serves it to Claude via MCP
"""
import json
import os
from flask import Flask, request, redirect, jsonify, Response

app = Flask(__name__)

_cache = {
    "ledger": [],
    "vouchers": [],
    "cashbook": [],
    "parties": [],
    "last_updated": ""
}

PUSH_SECRET = os.environ.get("PUSH_SECRET", "miracle_push_secret_2024")

def get_base_url():
    if request.headers.get('X-Forwarded-Proto'):
        scheme = request.headers.get('X-Forwarded-Proto')
    else:
        scheme = request.scheme
    host = request.headers.get('X-Forwarded-Host') or request.host
    return f"{scheme}://{host}"

@app.route("/")
def home():
    return jsonify({
        "status": "Miracle Connector Running",
        "version": "1.0",
        "last_updated": _cache["last_updated"],
        "records": {k: len(v) for k, v in _cache.items() if k != "last_updated"}
    })

@app.route("/push", methods=["POST"])
def push_data():
    secret = request.headers.get("X-Push-Secret", "")
    if secret != PUSH_SECRET:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(force=True, silent=True) or {}
    for key in ["ledger", "vouchers", "cashbook", "parties"]:
        if key in data:
            _cache[key] = data[key]
    from datetime import datetime
    _cache["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return jsonify({"status": "ok", "last_updated": _cache["last_updated"]})

@app.route("/.well-known/oauth-authorization-server")
@app.route("/.well-known/oauth-protected-resource")
def oauth_meta():
    base = get_base_url()
    return jsonify({
        "issuer": base,
        "authorization_endpoint": base + "/oauth/authorize",
        "token_endpoint": base + "/oauth/token",
        "registration_endpoint": base + "/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "scopes_supported": ["read"],
    })

@app.route("/register", methods=["POST", "GET"])
def register():
    data = request.get_json(force=True, silent=True) or {}
    redirect_uris = data.get("redirect_uris", [])
    return jsonify({
        "client_id": "miracle_client_id",
        "client_secret": "miracle_client_secret",
        "client_name": data.get("client_name", "Miracle Connector"),
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
    })

@app.route("/oauth/authorize")
def oauth_authorize():
    redirect_uri = request.args.get("redirect_uri", "")
    state = request.args.get("state", "")
    return redirect(f"{redirect_uri}?code=miracle_auth_code&state={state}")

@app.route("/oauth/token", methods=["POST", "GET"])
def oauth_token():
    return jsonify({
        "access_token": "miracle_static_access_token",
        "token_type": "Bearer",
        "expires_in": 99999999,
        "scope": "read",
    })

@app.route("/oauth/userinfo")
def oauth_userinfo():
    return jsonify({"id": "miracle", "name": "Miracle Connector", "email": "miracle@vinitmobile.in"})

TOOLS = {
    "get_ledger": {
        "description": "Get ledger accounts from Miracle accounting software",
        "inputSchema": {"type": "object", "properties": {
            "search": {"type": "string", "description": "Search by name"},
            "limit": {"type": "integer", "default": 50}
        }}
    },
    "get_vouchers": {
        "description": "Get vouchers/transactions from Miracle accounting software",
        "inputSchema": {"type": "object", "properties": {
            "date": {"type": "string", "description": "Filter by date"},
            "limit": {"type": "integer", "default": 100}
        }}
    },
    "get_cashbook": {
        "description": "Get cashbook entries from Miracle accounting software",
        "inputSchema": {"type": "object", "properties": {
            "limit": {"type": "integer", "default": 100}
        }}
    },
    "get_parties": {
        "description": "Get party/customer list from Miracle accounting software",
        "inputSchema": {"type": "object", "properties": {
            "search": {"type": "string", "description": "Search by name"},
            "limit":
