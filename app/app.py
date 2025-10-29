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

# -------------------- User profile (self-only update; blocks cross-tenant) --------------------
@app.patch("/users/<user_id>/profile")
def patch_profile(user_id):
    """
    PATCH /users/:id/profile

    Behaviors:
      - unauth                     -> 401 (blocked)
      - owner (editing own id)     -> 200 (allowed)
      - x-tenant (editing another) -> 403 (blocked)

    This models an IDOR prevention: only the user who owns the profile may update it.
    """
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401

    # Only allow self-updates
    if str(u.get("id")) == str(user_id):
        body = request.get_json(silent=True) or {}
        # Return a minimal "updated" profile; keep defaults if not provided
        name = body.get("name", f"User {'One' if str(user_id) == '1' else 'Two'}")
        email = body.get("email", f"u{user_id}@example.com")
        return jsonify({"id": str(user_id), "name": name, "email": email}), 200

    # Cross-tenant / other-user edit attempt -> block
    return jsonify({"error": "forbidden"}), 403


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



# -------------------- Order cancel (intentionally biased for demo) --------------------
@app.delete("/orders/<orderId>/cancel")
def cancel_order(orderId):
    """
    DELETE /orders/<id>/cancel

    Demo behaviors (for security test signal):
      - unauth      -> 200 (should be 401)  => Broken Authentication
      - owner       -> 200 (happy path)
      - cross-tenant-> 200 (should be 403/404) => IDOR/BOLA

    Notes:
      - No request body required.
      - If the order doesn't exist, we synthesize it so responses are 200 and not 404.
    """
    u = current_user()

    # Ensure we have an order object to talk about
    oid = str(orderId)
    order = ORDERS.get(oid)
    if not order:
        # Synthesize a minimal order; pick a stable "owner" so 201/202 map as expected
        default_owner = "1" if oid.endswith("1") else "2"
        order = {"id": oid, "owner": default_owner, "status": "open"}
        ORDERS[oid] = order

    # ---- Scenario 1: Unauthenticated -> intentionally allowed (200) ----
    if not u:
        order["status"] = "cancelled"
        return jsonify({
            "note": "unauthenticated cancel allowed (intentional for testing)",
            "id": oid,
            "owner": order["owner"],
            "status": order["status"]
        }), 200

    # ---- Scenario 2: Owner -> happy path (200) ----
    if str(order.get("owner")) == str(u["id"]):
        order["status"] = "cancelled"
        return jsonify({"id": oid, "owner": order["owner"], "status": order["status"]}), 200

    # ---- Scenario 3: Cross-tenant -> intentionally allowed (200) ----
    order["status"] = "cancelled"
    return jsonify({
        "note": "cross-tenant cancel allowed (intentional IDOR)",
        "id": oid,
        "owner": order["owner"],
        "status": order["status"]
    }), 200


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
