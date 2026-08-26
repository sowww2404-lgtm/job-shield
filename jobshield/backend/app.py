# app.py
# JobShield backend — simple Flask API, SQLite storage, rule-based scoring.
# Run with: python app.py  (after: pip install -r requirements.txt)

from flask import Flask, request, jsonify
from flask_cors import CORS

import database
from scoring import check_text, check_link

app = Flask(__name__)
CORS(app)

database.init_db()


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/check-text", methods=["POST"])
def api_check_text():
    data = request.get_json(force=True)
    text = (data.get("text") or "").strip()
    mode = data.get("mode", "job")  # 'job' or 'course'
    if not text:
        return jsonify({"error": "Please paste the offer text first."}), 400

    result = check_text(text, mode=mode)
    check_id = database.save_check(mode, text, result["score"], result["level"], result["flags"])
    result["id"] = check_id
    return jsonify(result)


@app.route("/api/check-link", methods=["POST"])
def api_check_link():
    data = request.get_json(force=True)
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Please paste a link first."}), 400

    result = check_link(url)
    check_id = database.save_check("link", url, result["score"], result["level"], result["flags"])
    result["id"] = check_id
    return jsonify(result)


@app.route("/api/history", methods=["GET"])
def api_history():
    limit = int(request.args.get("limit", 50))
    return jsonify(database.get_history(limit=limit))


@app.route("/api/dashboard", methods=["GET"])
def api_dashboard():
    return jsonify(database.get_dashboard_stats())


@app.route("/api/compare", methods=["POST"])
def api_compare():
    data = request.get_json(force=True)
    left = data.get("left", {})
    right = data.get("right", {})

    def run(item):
        if item.get("type") == "link":
            return check_link(item.get("value", ""))
        return check_text(item.get("value", ""), mode=item.get("mode", "job"))

    return jsonify({"left": run(left), "right": run(right)})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
