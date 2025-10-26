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
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401
    acc = ACCOUNTS.get(accountId)
    if not acc:
        return jsonify({"error": "not found"}), 404
    data = request.get_json(silent=True) or {}
    to_acc = data.get("toAccountId")
    amount = data.get("amount", 0)
    if to_acc not in ACCOUNTS:
        return jsonify({"error": "invalid target"}), 400
    # VULN: no ownership check -> any user can transfer from any account
    if amount <= 0 or acc["balance"] < amount:
        return jsonify({"error": "insufficient"}), 400
    acc["balance"] -= amount
    ACCOUNTS[to_acc]["balance"] += amount
    return jsonify({"from": acc["id"], "to": to_acc, "amount": amount}), 202

# -------------------- BFLA: cancel order (owner-only, but missing check) ----
@app.post("/orders/<orderId>/cancel")
def cancel_order(orderId):
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401
    order = ORDERS.get(orderId)
    if not order:
        return jsonify({"error": "not found"}), 404
    # VULN: no owner/admin check -> any user can cancel anyone's order
    order["status"] = "cancelled"
    return jsonify(order), 200

# -------------------- Admin-only (correctly enforced) ----------------------
@app.get("/admin/reports")
def admin_reports():
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401
    if u["role"] != "admin":
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"summary": "ok", "users": len(USERS), "orders": len(ORDERS)}), 200

@app.get("/me")
def me():
    u = current_user()
    if not u: return jsonify({"id": None, "role": None}), 401
    return jsonify({"id": u["id"], "role": u["role"]})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
