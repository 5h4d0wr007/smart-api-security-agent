from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# --------------------------------------------------------------------
# Demo data (two tenants, two users, two accounts, two orders)
# --------------------------------------------------------------------
USERS = {
    1: {"id": 1, "tenant": "tA", "name": "Alice"},
    2: {"id": 2, "tenant": "tB", "name": "Bob"},
}
ACCOUNTS = {
    101: {"id": 101, "tenant": "tA", "owner_user_id": 1, "balance": 1000},
    102: {"id": 102, "tenant": "tB", "owner_user_id": 2, "balance": 500},
}
ORDERS = {
    201: {"id": 201, "tenant": "tA", "owner_user_id": 1, "status": "NEW"},
    202: {"id": 202, "tenant": "tB", "owner_user_id": 2, "status": "NEW"},
}

TOKENS = {
    # bearer token -> (user_id, tenant, role)
    "t1": (1, "tA", "user"),
    "t2": (2, "tB", "user"),
    "admin": (999, "root", "admin"),
}

# --------------------------------------------------------------------
# Vulnerability profile — defaults to "demo" (vulnerable)
# --------------------------------------------------------------------
VULN_PROFILE = os.getenv("VULN_PROFILE", "demo").lower()
FLAGS = {
    "bola": VULN_PROFILE in ("demo", "bola", "all"),
    "bopla": VULN_PROFILE in ("demo", "bopla", "all"),
    "bfla": VULN_PROFILE in ("demo", "bfla", "all"),
}

def whoami():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        tok = auth.split(" ", 1)[1].strip()
        return TOKENS.get(tok)
    return None

def forbidden(msg="forbidden"): return jsonify({"error": msg}), 403
def unauth(): return jsonify({"error": "unauthorized"}), 401
def notfound(): return jsonify({"error": "not found"}), 404

# --------------------------------------------------------------------
# Endpoints (vulnerable depending on FLAGS)
# --------------------------------------------------------------------

@app.get("/")
def health():
    return jsonify({"ok": True})

@app.get("/admin/reports")
def admin_reports():
    me = whoami()
    if not me:
        return unauth()
    # BFLA: allow non-admins to read admin data when vulnerable
    if not FLAGS["bfla"] and me[2] != "admin":
        return forbidden("admin only")
    return jsonify({"reports": ["sales:123", "risks:7"]})

@app.patch("/users/<int:userId>/profile")
def update_profile(userId: int):
    me = whoami()
    if not me:
        return unauth()
    # BOLA: cross-user allowed when vulnerable
    if not FLAGS["bola"] and me[0] != userId:
        return forbidden("not your profile")
    return jsonify({"ok": True, "userId": userId})

@app.post("/accounts/<int:accountId>/transfer")
def transfer(accountId: int):
    me = whoami()
    if not me:
        return unauth()
    acct = ACCOUNTS.get(accountId)
    if not acct:
        return notfound()
    # BOPLA: cross-tenant & non-owner allowed when vulnerable
    if not FLAGS["bopla"]:
        if acct["tenant"] != me[1]:
            return forbidden("cross-tenant")
        if acct["owner_user_id"] != me[0]:
            return forbidden("not owner")
    amount = (request.json or {}).get("amount", 0)
    if not amount or amount < 0:
        return jsonify({"error": "invalid amount"}), 400
    return jsonify({"ok": True, "id": accountId})

@app.post("/orders/<int:orderId>/cancel")
def cancel(orderId: int):
    me = whoami()
    if not me:
        return unauth()
    order = ORDERS.get(orderId)
    if not order:
        return notfound()
    # BOPLA again
    if not FLAGS["bopla"]:
        if order["tenant"] != me[1]:
            return forbidden("cross-tenant")
        if order["owner_user_id"] != me[0]:
            return forbidden("not owner")
    order["status"] = "CANCELLED"
    return jsonify({"ok": True, "id": orderId})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
