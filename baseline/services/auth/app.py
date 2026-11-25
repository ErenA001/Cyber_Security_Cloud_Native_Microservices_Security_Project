import base64
from flask import Flask, request, jsonify
app = Flask(__name__)
USERS = {"admin": "admin123", "student": "1234"}   # INSECURE: sabit, zayif sifre

@app.route("/login", methods=["POST"])
def login():
    d = request.get_json(force=True)
    u, p = d.get("username"), d.get("password")
    if USERS.get(u) == p:
        return jsonify(token=base64.b64encode(u.encode()).decode())  # INSECURE: tahmin edilebilir token
    return jsonify(error="invalid credentials"), 401

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)   # INSECURE: debug acik
