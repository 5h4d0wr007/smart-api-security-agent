from flask import Flask, request, jsonify
app = Flask(__name__)

# Simple in-memory "DB"
PETS = {
    "11111111-1111-1111-1111-111111111111": {"id":"11111111-1111-1111-1111-111111111111","name":"Fido","type":"dog","owner":"u1"},
    "22222222-2222-2222-2222-222222222222": {"id":"22222222-2222-2222-2222-222222222222","name":"Milo","type":"cat","owner":"u2"},
}

def is_authed():
    # Treat any non-empty Bearer token as authenticated "u1"
    auth = request.headers.get("Authorization","")
    return auth.startswith("Bearer ")

def current_user():
    # pretend the token contains user id; return u1 if authed else None
    return "u1" if is_authed() else None

@app.get("/pets")
def list_pets():
    if not is_authed(): return ("", 401)
    return jsonify(list(PETS.values())), 200

@app.post("/pets")
def create_pet():
    if not is_authed(): return ("", 401)
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    typ  = (data.get("type") or "").strip()
    if not name or typ not in {"dog","cat","bird"}:
        return ("", 400)
    new_id = "33333333-3333-3333-3333-333333333333"
    PETS[new_id] = {"id":new_id,"name":name,"type":typ,"owner":current_user()}
    return jsonify(PETS[new_id]), 201

@app.get("/pets/<id>")
def get_pet(id):
    if not is_authed(): return ("", 401)
    pet = PETS.get(id)
    if not pet: return ("", 404)
    return jsonify(pet), 200

@app.patch("/pets/<id>")
def update_pet(id):
    if not is_authed(): return ("", 401)
    pet = PETS.get(id)
    if not pet: return ("", 404)
    data = request.get_json(force=True, silent=True) or {}
    if "name" in data and not str(data["name"]).strip():
        return ("", 400)
    pet.update({k:v for k,v in data.items() if k in {"name","type"}})
    return jsonify(pet), 200

@app.post("/pets/<id>/transfer")
def transfer_pet(id):
    if not is_authed(): return ("", 401)
    pet = PETS.get(id)
    if not pet: return ("", 404)
    user = current_user()
    if pet["owner"] != user:
        return ("", 403)  # can't transfer someone else's pet
    data = request.get_json(force=True, silent=True) or {}
    to_user = data.get("toUserId")
    transfer_id = data.get("transferId")
    if not to_user or not transfer_id:
        return ("", 400)
    # naive idempotency check
    if transfer_id == "dup":
        return ("", 409)
    pet["owner"] = to_user
    return ("", 202)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
