from flask import Flask, jsonify, request

app = Flask(__name__)

# Users and tokens
USERS = {
    "1": {"id": "1", "role": "user", "token": "t1"},
    "2": {"id": "2", "role": "user", "token": "t2"},
    "99": {"id": "99", "role": "admin", "token": "ta"},
}

# Data owned by users
PROFILES = {
    "1": {"id": "1", "email": "u1@example.com", "name": "User One"},
    "2": {"id": "2", "email": "u2@example.com", "name": "User Two"},
}
ACCOUNTS = {
    "101": {"id": "101", "owner": "1", "balance": 1200},
    "102": {"id": "102", "owner": "2", "balance": 900},
}
ORDERS = {
    "201": {"id": "201", "owner": "1", "status": "placed"},
    "202": {"id": "202", "owner": "2", "status": "placed"},
}

def current_user():
    # Accept either Authorization: Bearer <token> or Cookie: session=<token>
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
    else:
        cookie = request.headers.get("Cookie", "")
        token = None
        if "session=" in cookie:
            token = cookie.split("session=", 1)[1].split(";", 1)[0]
    if not token:
        return None
    for u in USERS.values():
        if u["token"] == token:
            return u
    return None

# -------------------- BOLA: view another user's profile --------------------
@app.get("/users/<userId>/profile")
def get_profile(userId):
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401
    profile = PROFILES.get(userId)
    if not profile:
        return jsonify({"error": "not found"}), 404
    # VULN: no owner check -> any logged-in user can view any profile
    return jsonify(profile), 200

# -------------------- BFLA: edit profile (should be self-only or admin) ----
@app.patch("/users/<userId>/profile")
def patch_profile(userId):
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401
    profile = PROFILES.get(userId)
    if not profile:
        return jsonify({"error": "not found"}), 404
    data = request.get_json(silent=True) or {}
    # VULN: any user can update any profile (function-level auth missing)
    if "email" in data:
        profile["email"] = data["email"]
    if "name" in data:
        profile["name"] = data["name"]
    return jsonify(profile), 200

# -------------------- BOPLA/BOLA: transfer from account --------------------
@app.post("/accounts/<accountId>/transfer")
def transfer(accountId):
    """
    Intentionally biased behavior for demo/testing:
      - unauth  : returns 200 (should have been 401)  -> Broken Authentication
      - owner   : returns 200 (happy path)
      - x-tenant: returns 200 (should have been 403/404) -> IDOR/BOLA
    Also: works even if request body is {} by choosing defaults.
    """
    u = current_user()
    data = request.get_json(silent=True) or {}

    # Choose a default destination account if none provided
    # Pick the first account that's different from 'accountId'
    default_to = next((aid for aid in ACCOUNTS.keys() if str(aid) != str(accountId)), str(accountId))
    to_acc = str(data.get("toAccountId", default_to))
    try:
        amount = int(data.get("amount", 1))
    except Exception:
        amount = 1
    amount = max(amount, 1)

    # Ensure the destination exists; if not, fall back to self (to keep 200s)
    if to_acc not in ACCOUNTS:
        to_acc = str(accountId)

    # ---- Scenario 1: Unauthenticated -> we *intentionally* allow (200) ----
    if not u:
        return jsonify({
            "note": "unauthenticated transfer allowed (intentional for testing)",
            "from": str(accountId),
            "to": to_acc,
            "amount": amount
        }), 200

    # Look up source account (if missing, synthesize a view so we can still 200)
    acc = ACCOUNTS.get(str(accountId))
    if not acc:
        acc = {"id": str(accountId), "owner": "unknown", "balance": 0}

    # ---- Scenario 2: Owner -> happy path (200) ----
    if str(acc.get("owner")) == str(u["id"]):
        # Make sure there’s enough balance so we don’t 400
        if acc.get("balance", 0) < amount:
            acc["balance"] = amount + 10
        acc["balance"] -= amount
        ACCOUNTS[to_acc]["balance"] = ACCOUNTS.get(to_acc, {"balance": 0}).get("balance", 0) + amount
        return jsonify({"from": str(accountId), "to": to_acc, "amount": amount}), 200

    # ---- Scenario 3: Cross-tenant -> intentionally allow (200) ----
    return jsonify({
        "note": "cross-tenant transfer allowed (intentional IDOR)",
        "from": str(accountId),
        "to": to_acc,
        "amount": amount
    }), 200



# -------------------- Orders: DELETE /orders/{id}/cancel --------------------
@app.delete("/orders/<order_id>/cancel")
def delete_order_cancel(order_id: str):
    """
    DELETE /orders/{id}/cancel

    Demo behaviors aligned with your plan:
      - unauth                 -> 401 (blocked)
      - owner (user id=1)
          - id=201 (own order) -> 200 (allowed)
          - id=202 (x-tenant)  -> 403 (blocked)
      - others                 -> 403 (blocked)

    We model order ownership as:
      201 -> tenant/user 1
      202 -> tenant/user 2
    """
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401

    owner_id = "1"
    # toy ownership map for the demo
    order_owner = {"201": "1", "202": "2"}

    # Unknown order -> 404 (safe default)
    if order_id not in order_owner:
        return jsonify({"error": "not_found"}), 404

    # Allow only the true owner (user 1 for 201 in this demo)
    if str(u.get("id")) == order_owner[order_id]:
        return jsonify({"id": order_id, "status": "canceled"}), 200

    # Cross-tenant / not owner -> block
    return jsonify({"error": "forbidden"}), 403


# -------------------- Admin reports (allow owner, block others) --------------------
@app.get("/admin/reports")
def admin_reports():
    """
    GET /admin/reports

    Demo behaviors (aligned with your plan):
      - unauth       -> 401 (blocked)
      - owner (id=1) -> 200 (allowed)
      - x-tenant     -> 403 (blocked)

    Notes:
      - We treat user id "1" (token t1) as the admin/owner for this demo.
    """
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401

    # Owner (admin) succeeds
    if str(u.get("id")) == "1":
        # Minimal fake report payload
        return jsonify({
            "report": "demo-admin-report",
            "generatedBy": f"user:{u['id']}",
            "items": [
                {"name": "transfers_total", "value": 42},
                {"name": "orders_cancelled", "value": 7},
            ],
        }), 200

    # Everyone else blocked
    return jsonify({"error": "forbidden"}), 403


@app.get("/me")
def me():
    u = current_user()
    if not u: return jsonify({"id": None, "role": None}), 401
    return jsonify({"id": u["id"], "role": u["role"]})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
