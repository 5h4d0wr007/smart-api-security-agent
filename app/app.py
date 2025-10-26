from flask import Flask, jsonify, request

app = Flask(__name__)

USERS = {
    "u1": {"id": "u1", "role": "user", "token": "token-user-u1"},
    "u2": {"id": "u2", "role": "user", "token": "token-user-u2"},
    "admin": {"id": "admin", "role": "admin", "token": "token-admin"},
}

PETS = {
    "p1": {"id": "p1", "name": "Fido", "owner": "u1", "type": "dog"},
    "p2": {"id": "p2", "name": "Milo", "owner": "u2", "type": "cat"},
}

def current_user():
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth.split(" ")[1]
        for u in USERS.values():
            if u["token"] == token:
                return u
    return None

# ----------------- BOLA -----------------
@app.get("/pets/<pid>")
def get_pet(pid):
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401
    pet = PETS.get(pid)
    if not pet:
        return jsonify({"error": "not found"}), 404
    # BOLA: no owner check
    return jsonify(pet), 200

# ----------------- BFLA -----------------
@app.patch("/pets/<pid>")
def update_pet(pid):
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401
    pet = PETS.get(pid)
    if not pet:
        return jsonify({"error": "not found"}), 404
    data = request.get_json(force=True, silent=True) or {}
    if "owner" in data:
        # BFLA: non-admin users can transfer ownership
        pet["owner"] = data["owner"]
    if "name" in data:
        pet["name"] = data["name"]
    return jsonify(pet), 200

# ----------------- Safe transfer -----------------
@app.post("/pets/<pid>/transfer")
def transfer_pet(pid):
    u = current_user()
    if not u:
        return jsonify({"error": "unauthenticated"}), 401
    pet = PETS.get(pid)
    if not pet:
        return jsonify({"error": "not found"}), 404
    if pet["owner"] != u["id"]:
        return jsonify({"error": "forbidden"}), 403
    data = request.get_json(force=True, silent=True) or {}
    to_user = data.get("toUserId")
    if to_user not in USERS:
        return jsonify({"error": "invalid target"}), 400
    pet["owner"] = to_user
    return jsonify(pet), 202

@app.get("/me")
def whoami():
    u = current_user()
    if not u:
        return jsonify({"id": None, "role": None}), 401
    return jsonify({"id": u["id"], "role": u["role"]})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
