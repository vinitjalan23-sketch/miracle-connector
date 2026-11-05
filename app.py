"""
Miracle Connector - Render deployment
Receives DBF data pushed from Windows server, serves it to Claude via MCP
"""
import json
import os
from flask import Flask, request, redirect, jsonify, Response

app = Flask(__name__)

# In-memory cache for data pushed from server
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

# --- Data
