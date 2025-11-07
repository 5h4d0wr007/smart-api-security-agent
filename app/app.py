from flask import Flask, jsonify, request

app = Flask(__name__)

#in-memory for mocking user DB, and simulating sec. tests with this data. You can integrate the agent with your own app
USERS = {
    "1": {"id": "1", "role": "user", "token": "t1"},
    "2": {"id": "2", "role": "user", "token": "t2"},
    "99": {"id": "99", "role": "admin", "token": "ta"},
}

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
    #mocking to accept either Authorization: Bearer <token> or Cookie: session=<token>
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
    

@app.get("/users/<userId>/profile")
def get_profile(userId):
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401
    profile = PROFILES.get(userId) #intentional; for our agent to catch and report
    if not profile:
        return jsonify({"error": "not found"}), 404
    #v1: no owner check -> any logged-in user can view any profile
    return jsonify(profile), 200

@app.patch("/users/<user_id>/profile")
def patch_profile(user_id):
    #only the user who owns the profile can update
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401

    if str(u.get("id")) == str(user_id):
        body = request.get_json(silent=True) or {}
        name = body.get("name", f"User {'One' if str(user_id) == '1' else 'Two'}")
        email = body.get("email", f"u{user_id}@example.com")
        return jsonify({"id": str(user_id), "name": name, "email": email}), 200
        
    return jsonify({"error": "forbidden"}), 403


@app.post("/accounts/<accountId>/transfer")
def transfer(accountId):
    u = current_user()
    data = request.get_json(silent=True) or {}
    default_to = next((aid for aid in ACCOUNTS.keys() if str(aid) != str(accountId)), str(accountId))
    to_acc = str(data.get("toAccountId", default_to))
    try:
        amount = int(data.get("amount", 1))
    except Exception:
        amount = 1 #mock to always be on
    amount = max(amount, 1)

    if to_acc not in ACCOUNTS:
        to_acc = str(accountId)

    if not u:
        return jsonify({
            "note": "success",
            "from": str(accountId),
            "to": to_acc,
            "amount": amount
        }), 200 #v2: broken authN

    acc = ACCOUNTS.get(str(accountId))
    if not acc:
        acc = {"id": str(accountId), "owner": "unknown", "balance": 0}

    if str(acc.get("owner")) == str(u["id"]):
        if acc.get("balance", 0) < amount:
            acc["balance"] = amount + 10
        acc["balance"] -= amount
        ACCOUNTS[to_acc]["balance"] = ACCOUNTS.get(to_acc, {"balance": 0}).get("balance", 0) + amount
        return jsonify({"from": str(accountId), "to": to_acc, "amount": amount}), 200

    return jsonify({
        "note": "cross-tenant transfer allowed (intentional IDOR)",
        "from": str(accountId),
        "to": to_acc,
        "amount": amount
    }), 200 #v3: broken authZ


@app.delete("/orders/<orderId>/cancel")
def cancel_order(orderId):
    u = current_user()
    oid = str(orderId)
    order = ORDERS.get(oid)
    if not order:
        default_owner = "1" if oid.endswith("1") else "2"
        order = {"id": oid, "owner": default_owner, "status": "open"}
        ORDERS[oid] = order

    if not u:
        order["status"] = "cancelled"
        return jsonify({
            "note": "unauthenticated cancel allowed (intentional for testing)",
            "id": oid,
            "owner": order["owner"],
            "status": order["status"]
        }), 200 #v4: broken authN

    if str(order.get("owner")) == str(u["id"]):
        order["status"] = "cancelled"
        return jsonify({"id": oid, "owner": order["owner"], "status": order["status"]}), 200

    order["status"] = "cancelled"
    return jsonify({
        "note": "cross-tenant cancel allowed (intentional IDOR)",
        "id": oid,
        "owner": order["owner"],
        "status": order["status"]
    }), 200 #v5: broken authZ - kept separate for proper capture


@app.get("/admin/reports")
def admin_reports():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer", "").strip()

    if not token:
        return jsonify({"error": "unauthenticated"}), 401

    if token == "t1":
        return jsonify({
            "report": "admin-metrics",
            "totals": {"users": 2, "orders": 3, "failed_logins": 0}
        }), 200

    return jsonify({"error": "forbidden"}), 403

@app.get("/me")
def me():
    u = current_user()
    if not u: return jsonify({"id": None, "role": None}), 401
    return jsonify({"id": u["id"], "role": u["role"]})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
