"""
Intentionally vulnerable sample — IDOR in user profile endpoint.
Used for Pass 4 business logic discovery testing.
DO NOT deploy this code.
"""
from flask import Flask, request, jsonify, session

app = Flask(__name__)
app.secret_key = "dev-secret"

# Simulated user database
USERS = {
    1: {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "user", "ssn": "123-45-6789"},
    2: {"id": 2, "name": "Bob", "email": "bob@example.com", "role": "admin", "ssn": "987-65-4321"},
    3: {"id": 3, "name": "Carol", "email": "carol@example.com", "role": "user", "ssn": "111-22-3333"},
}

POSTS = {
    1: {"id": 1, "user_id": 1, "content": "Alice's private post"},
    2: {"id": 2, "user_id": 2, "content": "Bob's private post"},
}


@app.route("/api/user/<int:user_id>", methods=["GET"])
def get_user_profile(user_id):
    # IDOR: no ownership check — any authenticated user can read any profile including SSN
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "Not found"}), 404
    return jsonify(user)  # Returns SSN — info disclosure


@app.route("/api/user/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    # Mass assignment: all fields from request body applied without whitelist
    if "user_id" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    user = USERS.get(user_id)
    if not user:
        return jsonify({"error": "Not found"}), 404
    data = request.json or {}
    user.update(data)  # Attacker can set role=admin
    return jsonify(user)


@app.route("/api/post/<int:post_id>", methods=["GET"])
def get_post(post_id):
    # IDOR: reads post without checking post.user_id == session["user_id"]
    post = POSTS.get(post_id)
    if not post:
        return jsonify({"error": "Not found"}), 404
    return jsonify(post)


@app.route("/api/transfer", methods=["POST"])
def transfer_funds():
    # Race condition: check-then-act without atomic transaction
    data = request.json or {}
    amount = data.get("amount", 0)
    from_user = USERS.get(session.get("user_id"))
    if not from_user:
        return jsonify({"error": "Not authenticated"}), 401
    balance = from_user.get("balance", 100)
    if balance >= amount:  # TOCTOU — another request can deplete balance between check and deduct
        from_user["balance"] = balance - amount
        return jsonify({"new_balance": from_user["balance"]})
    return jsonify({"error": "Insufficient funds"}), 400


@app.route("/api/admin/users", methods=["GET"])
def list_all_users():
    # Broken auth: checks role in request body instead of session
    data = request.json or {}
    if data.get("role") == "admin":  # Attacker sends {"role": "admin"}
        return jsonify(list(USERS.values()))
    return jsonify({"error": "Forbidden"}), 403
