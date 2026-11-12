"""
Miracle Connector (Render) - serves Miracle accounting data to Claude via MCP.
Data lives in Supabase (persistent). A sync script on the Windows server fills it.
Access is protected by a password (MIRACLE_PASSWORD) through the OAuth screen.

Environment variables (set on Render, never in the repo):
  SUPABASE_URL      e.g. https://xxxx.supabase.co
  SUPABASE_KEY      new secret key (sb_secret_...)
  MIRACLE_PASSWORD  password asked once when connecting the connector in Claude
  SIGN_SECRET       any long random text (used to sign tokens)
"""
# gevent must patch BEFORE ssl/requests are imported, else "maximum recursion depth exceeded" on https calls
try:
    from gevent import monkey
    monkey.patch_all()
except Exception:
    pass

import base64, hashlib, hmac, json, os, time
from datetime import date
from html import escape
from urllib.parse import urlencode

import requests
from flask import Flask, Response, jsonify, redirect, request

app = Flask(__name__)

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
PASSWORD = os.environ.get("MIRACLE_PASSWORD", "")
SIGN_SECRET = os.environ.get("SIGN_SECRET", "")


# ---------------------------------------------------------------- auth helpers
def _sig(msg: str) -> str:
    return hmac.new(SIGN_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()


def _b64(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def _unb64(s: str) -> str:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode()


def make_code(challenge: str) -> str:
    body = _b64(json.dumps({"ts": int(time.time()), "ch": challenge or ""}))
    return body + "." + _sig("code." + body)


def read_code(code: str):
    try:
        body, sig = code.split(".")
        if not hmac.compare_digest(sig, _sig("code." + body)):
            return None
        data = json.loads(_unb64(body))
        if time.time() - data["ts"] > 600:
            return None
        return data
    except Exception:
        return None


def access_token() -> str:
    return "mir_" + _sig("access-token")[:48]


def authed() -> bool:
    if not SIGN_SECRET:
        return False
    h = request.headers.get("Authorization", "")
    return h.startswith("Bearer ") and hmac.compare_digest(h[7:], access_token())


def base_url() -> str:
    proto = request.headers.get("X-Forwarded-Proto", request.scheme)
    host = request.headers.get("X-Forwarded-Host") or request.host
    return f"{proto}://{host}"


# ---------------------------------------------------------------- OAuth (password protected)
@app.route("/.well-known/oauth-protected-resource")
@app.route("/.well-known/oauth-protected-resource/mcp")
def oauth_resource():
    b = base_url()
    return jsonify({"resource": b + "/mcp", "authorization_servers": [b]})


@app.route("/.well-known/oauth-authorization-server")
def oauth_meta():
    b = base_url()
    return jsonify({
        "issuer": b,
        "authorization_endpoint": b + "/oauth/authorize",
        "token_endpoint": b + "/oauth/token",
        "registration_endpoint": b + "/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
    })


@app.route("/register", methods=["POST"])
def register():
    d = request.get_json(force=True, silent=True) or {}
    return jsonify({
        "client_id": "miracle_client", "client_name": d.get("client_name", "Claude"),
        "redirect_uris": d.get("redirect_uris", []), "grant_types": ["authorization_code"],
        "response_types": ["code"], "token_endpoint_auth_method": "none",
    }), 201


FORM = """<html><body style="font-family:sans-serif;max-width:360px;margin:80px auto">
<h3>Miracle Accounting - Claude Access</h3>
<form method="post">
<input type="hidden" name="redirect_uri" value="{ru}"><input type="hidden" name="state" value="{st}">
<input type="hidden" name="code_challenge" value="{ch}">
<p>Password:</p><input type="password" name="password" style="width:100%;padding:8px" autofocus>
<p style="color:#c00">{err}</p>
<button style="padding:10px 20px">Allow</button></form></body></html>"""


@app.route("/oauth/authorize", methods=["GET", "POST"])
def oauth_authorize():
    src = request.form if request.method == "POST" else request.args
    ru, st, ch = src.get("redirect_uri", ""), src.get("state", ""), src.get("code_challenge", "")
    if request.method == "POST":
        if PASSWORD and SIGN_SECRET and hmac.compare_digest(request.form.get("password", ""), PASSWORD):
            q = urlencode({"code": make_code(ch), "state": st})
            return redirect(ru + ("&" if "?" in ru else "?") + q)
        return FORM.format(ru=escape(ru), st=escape(st), ch=escape(ch), err="Wrong password"), 401
    return FORM.format(ru=escape(ru), st=escape(st), ch=escape(ch), err="")


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    f = request.form or (request.get_json(silent=True) or {})
    data = read_code(f.get("code", ""))
    if not data:
        return jsonify({"error": "invalid_grant"}), 400
    if data["ch"]:
        v = f.get("code_verifier", "")
        calc = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).decode().rstrip("=")
        if not hmac.compare_digest(calc, data["ch"]):
            return jsonify({"error": "invalid_grant"}), 400
    return jsonify({"access_token": access_token(), "token_type": "Bearer", "expires_in": 31536000})


# ---------------------------------------------------------------- Supabase access
def sb_get(table, params, limit=None):
    h = {"apikey": SUPABASE_KEY, "Authorization": "Bearer " + SUPABASE_KEY}
    out, off, page = [], 0, 1000
    while True:
        want = page if limit is None else min(page, limit - len(out))
        if want <= 0:
            break
        p = dict(params); p["limit"] = want; p["offset"] = off
        r = requests.get(f"{SUPABASE_URL}/rest/v1/{table}", headers=h, params=p, timeout=60)
        if r.status_code >= 300:
            raise RuntimeError(f"database error {r.status_code}: {r.text[:200]}")
        rows = r.json(); out += rows; off += len(rows)
        if len(rows) < want:
            break
    return out


def sb_rpc(fn, body):
    h = {"apikey": SUPABASE_KEY, "Authorization": "Bearer " + SUPABASE_KEY, "Content-Type": "application/json"}
    r = requests.post(f"{SUPABASE_URL}/rest/v1/rpc/{fn}", headers=h, data=json.dumps(body), timeout=60)
    if r.status_code >= 300:
        raise RuntimeError(f"database error {r.status_code}: {r.text[:200]}")
    return r.json()


def resolve_company(c):
    comps = sb_get("miracle_companies", {"select": "company_no,name", "order": "company_no"})
    c = (c or "").strip()
    if c:
        hit = [x for x in comps if x["company_no"] == c.zfill(4) or x["company_no"] == c]
        if not hit:
            hit = [x for x in comps if clean_q(c).lower() in x["name"].lower()]
    else:
        hit = comps
    if len(hit) == 1:
        return hit[0], None
    return None, {"message": "Pick one company (pass company_no)", "companies": hit}


def clean_q(q):
    return "".join(ch for ch in (q or "") if ch not in ",()*:\"'\\%&").strip()


def resolve_ledger(cno, q):
    q = clean_q(q)
    rows = sb_get("miracle_ledger_latest", {"select": "code,name,group_code,kind,city", "company_no": "eq." + cno,
                                            "or": f"(code.eq.{q},name.ilike.*{q}*)", "order": "name"}, limit=50)
    return rows


# ---------------------------------------------------------------- tools
def money(x):
    return round(float(x), 2)


def t_companies(a):
    comps = sb_get("miracle_companies", {"select": "company_no,name", "order": "company_no"})
    log = sb_get("miracle_sync_log", {"select": "synced_at,note", "order": "id.desc"}, limit=1)
    return {"companies": comps, "last_sync": log[0] if log else None}


def t_find_ledger(a):
    comp, err = resolve_company(a.get("company"))
    if err: return err
    return {"company": comp["name"], "ledgers": resolve_ledger(comp["company_no"], a.get("search", ""))}


def t_statement(a):
    comp, err = resolve_company(a.get("company"))
    if err: return err
    cno = comp["company_no"]
    ledgers = resolve_ledger(cno, a.get("ledger", ""))
    if not ledgers:
        return {"error": "ledger not found", "company": comp["name"]}
    if len(ledgers) > 1:
        q = clean_q(a.get("ledger", "")).lower()
        exact = [x for x in ledgers if x["code"].lower() == q or (x["name"] or "").strip().lower() == q]
        if len(exact) == 1:
            ledgers = exact
    if len(ledgers) > 1:
        return {"message": "Several ledgers match, pass the exact code", "matches": ledgers}
    led = ledgers[0]
    frm = a.get("from_date") or "1900-01-01"
    to = a.get("to_date") or date.today().isoformat()
    opening = float(sb_rpc("miracle_opening", {"p_company": cno, "p_account": led["code"], "p_before": frm}))
    rows = sb_get("miracle_entries", {
        "select": "vdate,vtype,vno,contra_code,dc,amount,narration", "company_no": "eq." + cno,
        "account_code": "eq." + led["code"], "and": f"(vdate.gte.{frm},vdate.lte.{to})",
        "order": "vdate,id"}, limit=int(a.get("limit", 500)))
    names = {x["code"]: x["name"] for x in sb_get("miracle_ledger_latest", {
        "select": "code,name", "company_no": "eq." + cno,
        "code": "in.(" + ",".join(sorted({r["contra_code"] for r in rows if r["contra_code"]})) + ")"})} if rows else {}
    bal, out, dr, cr = opening, [], 0.0, 0.0
    for r in rows:
        amt = float(r["amount"])
        if r["dc"] == "D": bal += amt; dr += amt
        else: bal -= amt; cr += amt
        out.append({"date": r["vdate"], "type": r["vtype"], "vno": r["vno"], "against": names.get(r["contra_code"], r["contra_code"]),
                    "debit": money(amt) if r["dc"] == "D" else 0, "credit": money(amt) if r["dc"] == "C" else 0,
                    "balance": money(bal), "narration": r["narration"]})
    side = lambda v: f"{abs(money(v))} {'Dr' if v >= 0 else 'Cr'}"
    return {"company": comp["name"], "ledger": led["name"], "code": led["code"], "from": frm, "to": to,
            "opening": side(opening), "total_debit": money(dr), "total_credit": money(cr), "closing": side(bal),
            "entries": out, "note": "balance is Dr(+) / Cr(-); opening = all earlier years + earlier dates"}


def t_trial(a):
    comp, err = resolve_company(a.get("company"))
    if err: return err
    rows = sb_rpc("miracle_trial_balance", {"p_company": comp["company_no"], "p_asof": a.get("as_of") or date.today().isoformat()})
    q = (a.get("search") or "").lower()
    if q: rows = [r for r in rows if q in (r["account_name"] or "").lower()]
    rows.sort(key=lambda r: -abs(float(r["net"])))
    lim = int(a.get("limit", 100))
    return {"company": comp["name"], "as_of": a.get("as_of") or date.today().isoformat(), "count": len(rows),
            "total_debit": money(sum(float(r["debit"]) for r in rows)), "total_credit": money(sum(float(r["credit"]) for r in rows)),
            "accounts": [{"code": r["account_code"], "name": r["account_name"], "net_dr_positive": money(r["net"])} for r in rows[:lim]]}


def t_vouchers(a):
    comp, err = resolve_company(a.get("company"))
    if err: return err
    cno = comp["company_no"]
    p = {"select": "voucher_id,vdate,vtype,vno,account_code,contra_code,dc,amount,narration", "company_no": "eq." + cno,
         "order": "vdate.desc,id.desc"}
    conds = []
    if a.get("from_date"): conds.append("vdate.gte." + a["from_date"])
    if a.get("to_date"): conds.append("vdate.lte." + a["to_date"])
    if conds: p["and"] = "(" + ",".join(conds) + ")"
    if a.get("vtype"): p["vtype"] = "eq." + a["vtype"].upper()
    if a.get("search"): p["narration"] = "ilike.*" + clean_q(a["search"]) + "*"
    rows = sb_get("miracle_entries", p, limit=int(a.get("limit", 100)))
    ids = sorted({r["account_code"] for r in rows} | {r["contra_code"] for r in rows if r["contra_code"]})
    names = {x["code"]: x["name"] for x in sb_get("miracle_ledger_latest", {
        "select": "code,name", "company_no": "eq." + cno, "code": "in.(" + ",".join(ids) + ")"})} if ids else {}
    return {"company": comp["name"], "count": len(rows), "entries": [
        {"date": r["vdate"], "type": r["vtype"], "vno": r["vno"], "account": names.get(r["account_code"], r["account_code"]),
         "dc": r["dc"], "amount": money(r["amount"]), "against": names.get(r["contra_code"], r["contra_code"]),
         "narration": r["narration"]} for r in rows]}


def _names(table, cno, codes):
    codes = sorted({c for c in codes if c})
    if not codes: return {}
    return {x["code"]: x["name"] for x in sb_get(table, {"select": "code,name", "company_no": "eq." + cno,
                                                         "code": "in.(" + ",".join(codes) + ")"})}


def _party_codes(cno, q):
    return [x["code"] for x in resolve_ledger(cno, q)]


def _item_codes(cno, q):
    q = clean_q(q)
    return [x["code"] for x in sb_get("miracle_item_latest", {"select": "code,name", "company_no": "eq." + cno,
                                                              "or": f"(code.eq.{q},name.ilike.*{q}*)"}, limit=200)]


def t_imei(a):
    comp, err = resolve_company(a.get("company"))
    if err: return err
    cno = comp["company_no"]
    p = {"select": "imei,serial2,item_code,pur_voucher,pur_date,pur_party,pur_rate,sale_voucher,sale_date,sale_vno,sale_party,sale_rate,sold,year_no",
         "company_no": "eq." + cno, "order": "pur_date.desc"}
    src = "miracle_imei"
    if a.get("imei"): p["imei"] = "ilike.*" + clean_q(a["imei"]) + "*"
    else: src = "miracle_imei_latest"        # list mode: one row per phone
    if a.get("status") == "sold": p["sold"] = "eq.true"
    if a.get("status") == "instock": p["sold"] = "eq.false"
    if a.get("item"):
        codes = _item_codes(cno, a["item"])
        if not codes: return {"message": "no item matches", "company": comp["name"]}
        p["item_code"] = "in.(" + ",".join(codes) + ")"
    if a.get("sold_to"):
        codes = _party_codes(cno, a["sold_to"])
        if not codes: return {"message": "no party matches", "company": comp["name"]}
        p["sale_party"] = "in.(" + ",".join(codes) + ")"
    if a.get("bought_from"):
        codes = _party_codes(cno, a["bought_from"])
        if not codes: return {"message": "no party matches", "company": comp["name"]}
        p["pur_party"] = "in.(" + ",".join(codes) + ")"
    conds = []
    if a.get("from_date"): conds.append("sale_date.gte." + a["from_date"])
    if a.get("to_date"): conds.append("sale_date.lte." + a["to_date"])
    if conds: p["and"] = "(" + ",".join(conds) + ")"
    rows = sb_get(src, p, limit=int(a.get("limit", 50)))
    items = _names("miracle_item_latest", cno, [r["item_code"] for r in rows])
    parties = _names("miracle_ledger_latest", cno, [r["pur_party"] for r in rows] + [r["sale_party"] for r in rows])
    return {"company": comp["name"], "count": len(rows), "phones": [
        {"imei": r["imei"], "serial2": r["serial2"], "item": items.get(r["item_code"], r["item_code"]),
         "bought_on": r["pur_date"], "bought_from": parties.get(r["pur_party"], r["pur_party"]), "cost": money(r["pur_rate"] or 0),
         "status": "sold" if r["sold"] else "in stock",
         "sold_on": r["sale_date"], "sold_to": parties.get(r["sale_party"], r["sale_party"]) or None,
         "sale_bill": r["sale_vno"] or None, "sale_rate": money(r["sale_rate"] or 0) if r["sold"] else None} for r in rows]}


def t_stock(a):
    comp, err = resolve_company(a.get("company"))
    if err: return err
    rows = sb_rpc("miracle_stock_summary", {"p_company": comp["company_no"], "p_search": clean_q(a.get("search", ""))})
    lim = int(a.get("limit", 100))
    return {"company": comp["name"], "total_phones_in_stock": sum(int(r["in_stock"]) for r in rows), "models": len(rows),
            "items": [{"item": r["item_name"] or r["item_code"], "in_stock": r["in_stock"], "avg_cost": money(r["avg_cost"] or 0)} for r in rows[:lim]],
            "note": "stock = IMEIs bought but not yet sold, as per Miracle serial-number records"}


def t_item_lines(a):
    comp, err = resolve_company(a.get("company"))
    if err: return err
    cno = comp["company_no"]
    p = {"select": "voucher_id,vdate,vtype,item_code,dc,qty,rate,amount,party_code", "company_no": "eq." + cno,
         "order": "vdate.desc,id.desc"}
    conds = []
    if a.get("from_date"): conds.append("vdate.gte." + a["from_date"])
    if a.get("to_date"): conds.append("vdate.lte." + a["to_date"])
    if conds: p["and"] = "(" + ",".join(conds) + ")"
    if a.get("vtype"): p["vtype"] = "eq." + a["vtype"].upper()
    if a.get("item"):
        codes = _item_codes(cno, a["item"])
        if not codes: return {"message": "no item matches", "company": comp["name"]}
        p["item_code"] = "in.(" + ",".join(codes) + ")"
    if a.get("party"):
        codes = _party_codes(cno, a["party"])
        if not codes: return {"message": "no party matches", "company": comp["name"]}
        p["party_code"] = "in.(" + ",".join(codes) + ")"
    rows = sb_get("miracle_item_lines", p, limit=int(a.get("limit", 200)))
    items = _names("miracle_item_latest", cno, [r["item_code"] for r in rows])
    parties = _names("miracle_ledger_latest", cno, [r["party_code"] for r in rows])
    return {"company": comp["name"], "count": len(rows), "total_qty": money(sum(float(r["qty"] or 0) for r in rows)),
            "total_amount": money(sum(float(r["amount"] or 0) for r in rows)), "lines": [
        {"date": r["vdate"], "type": r["vtype"], "item": items.get(r["item_code"], r["item_code"]), "qty": float(r["qty"] or 0),
         "rate": money(r["rate"] or 0), "amount": money(r["amount"] or 0), "party": parties.get(r["party_code"], r["party_code"])} for r in rows],
            "note": "vtype SS = sales, PP = purchase. Amounts as per Miracle item lines (before extra charges/discounts on the bill)"}


COMP = {"type": "string", "description": "Company name part (e.g. 'surat') or number (e.g. 0003)"}
TOOLS = {
    "miracle_companies": ("List Miracle companies and when data was last synced", {"type": "object", "properties": {}}, t_companies),
    "miracle_find_ledger": ("Search ledger accounts (parties, banks, etc.) by name or code in one company",
                            {"type": "object", "properties": {"company": COMP, "search": {"type": "string"}}, "required": ["company", "search"]}, t_find_ledger),
    "miracle_ledger_statement": ("Account statement of one ledger with opening, running balance and closing",
                                 {"type": "object", "properties": {"company": COMP, "ledger": {"type": "string", "description": "ledger name or code"},
                                  "from_date": {"type": "string", "description": "YYYY-MM-DD"}, "to_date": {"type": "string", "description": "YYYY-MM-DD"},
                                  "limit": {"type": "integer", "default": 500}}, "required": ["company", "ledger"]}, t_statement),
    "miracle_trial_balance": ("Closing balance of all ledgers as on a date (all years together)",
                              {"type": "object", "properties": {"company": COMP, "as_of": {"type": "string", "description": "YYYY-MM-DD"},
                               "search": {"type": "string"}, "limit": {"type": "integer", "default": 100}}, "required": ["company"]}, t_trial),
    "miracle_vouchers": ("Voucher entries (day book) with filters on date, voucher type (CR,CP,BR,BP,BC,JR,SS,PP) and narration text",
                         {"type": "object", "properties": {"company": COMP, "from_date": {"type": "string"}, "to_date": {"type": "string"},
                          "vtype": {"type": "string"}, "search": {"type": "string"}, "limit": {"type": "integer", "default": 100}}, "required": ["company"]}, t_vouchers),
    "miracle_imei": ("Phone/IMEI records: look up an IMEI (full or partial), or list phones by item, status (sold/instock), sold_to or bought_from party and sale date range. Shows purchase and sale details.",
                     {"type": "object", "properties": {"company": COMP, "imei": {"type": "string"}, "item": {"type": "string", "description": "model name part"},
                      "status": {"type": "string", "enum": ["sold", "instock"]}, "sold_to": {"type": "string", "description": "customer/party name"},
                      "bought_from": {"type": "string", "description": "supplier name"}, "from_date": {"type": "string", "description": "sale date from, YYYY-MM-DD"},
                      "to_date": {"type": "string"}, "limit": {"type": "integer", "default": 50}}, "required": ["company"]}, t_imei),
    "miracle_stock": ("Phones currently in stock (bought, not sold) model-wise with counts and average cost",
                      {"type": "object", "properties": {"company": COMP, "search": {"type": "string", "description": "model name part"},
                       "limit": {"type": "integer", "default": 100}}, "required": ["company"]}, t_stock),
    "miracle_item_lines": ("Item-wise sales/purchase lines (qty, rate, amount) with filters on item, party, voucher type SS/PP and dates",
                           {"type": "object", "properties": {"company": COMP, "item": {"type": "string"}, "party": {"type": "string"},
                            "vtype": {"type": "string", "description": "SS sales or PP purchase"}, "from_date": {"type": "string"},
                            "to_date": {"type": "string"}, "limit": {"type": "integer", "default": 200}}, "required": ["company"]}, t_item_lines),
}


def rpc(body):
    m, rid = body.get("method", ""), body.get("id")
    ok = lambda r: jsonify({"jsonrpc": "2.0", "id": rid, "result": r})
    if m == "initialize":
        return ok({"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "Miracle Connector", "version": "2.2"}})
    if m.startswith("notifications/"):
        return ("", 202)
    if m == "tools/list":
        return ok({"tools": [{"name": k, "description": v[0], "inputSchema": v[1]} for k, v in TOOLS.items()]})
    if m == "tools/call":
        p = body.get("params", {}); t = TOOLS.get(p.get("name"))
        if not t:
            return jsonify({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Unknown tool"}})
        try:
            res, err = t[2](p.get("arguments", {}) or {}), False
        except Exception as ex:
            res, err = {"error": str(ex)}, True
        return ok({"content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False, default=str)}], "isError": err})
    return jsonify({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found"}})


@app.route("/mcp", methods=["GET", "POST", "DELETE"])
def mcp_endpoint():
    if not authed():
        b = base_url()
        return Response("unauthorized", 401, {"WWW-Authenticate": f'Bearer resource_metadata="{b}/.well-known/oauth-protected-resource"'})
    if request.method != "POST":
        return jsonify({"name": "Miracle Connector", "version": "2.2"})
    return rpc(request.get_json(force=True, silent=True) or {})


@app.route("/")
def home():
    return jsonify({"status": "Miracle Connector running", "version": "2.2"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
