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
    return jsonify({
        "client_id": "miracle_client_id",
        "client_secret": "miracle_client_secret",
        "client_name": "Miracle Connector",
        "redirect_uris": [],
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
            "limit": {"type": "integer", "default": 50}
        }}
    },
}

def call_tool(name, args):
    def search_filter(records, search_key, search_val, limit):
        if not search_val:
            return records[:limit]
        return [r for r in records if search_val.lower() in str(r.get(search_key, "")).lower()][:limit]

    if name == "get_ledger":
        data = search_filter(_cache["ledger"], "NAME", args.get("search", ""), args.get("limit", 50))
        return json.dumps(data, ensure_ascii=False)
    elif name == "get_vouchers":
        data = search_filter(_cache["vouchers"], "DATE", args.get("date", ""), args.get("limit", 100))
        return json.dumps(data, ensure_ascii=False)
    elif name == "get_cashbook":
        return json.dumps(_cache["cashbook"][:args.get("limit", 100)], ensure_ascii=False)
    elif name == "get_parties":
        data = search_filter(_cache["parties"], "NAME", args.get("search", ""), args.get("limit", 50))
        return json.dumps(data, ensure_ascii=False)
    return "Unknown tool"

@app.route("/mcp", methods=["GET", "POST"])
def mcp_endpoint():
    if request.method == "GET":
        def sse():
            init = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
            yield f"data: {json.dumps(init)}\n\n"
        return Response(sse(), mimetype="text/event-stream")

    body = request.get_json(force=True, silent=True) or {}
    method = body.get("method", "")
    req_id = body.get("id")

    if method == "initialize":
        return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "Miracle Connector", "version": "1.0"}
        }})
    elif method == "tools/list":
        tools_list = [{"name": k, "description": v["description"], "inputSchema": v["inputSchema"]} for k, v in TOOLS.items()]
        return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools_list}})
    elif method == "tools/call":
        params = body.get("params", {})
        result = call_tool(params.get("name", ""), params.get("arguments", {}))
        return jsonify({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": result}]}})
    else:
        return jsonify({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": "Method not found"}})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
