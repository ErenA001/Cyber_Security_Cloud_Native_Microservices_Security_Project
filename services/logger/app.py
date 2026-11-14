from flask import Flask, request, jsonify
app = Flask(__name__)
LOGS = []

@app.route("/log", methods=["POST"])
def add():
    LOGS.append(request.get_json(force=True))
    return jsonify(ok=True)

@app.route("/logs")                      # INSECURE: herkes tum loglari okuyabilir
def get():
    return jsonify(LOGS)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
