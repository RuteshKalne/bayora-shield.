from flask import Flask, jsonify, request, send_from_directory
from guardrail import evaluate_scenario
from ledger import AuditLedger

app = Flask(__name__)
ledger = AuditLedger()

VALID_SESSIONS = {
    "session-alpha",
    "session-bravo",
    "session-charlie",
}
MAX_PROMPT_LENGTH = 5000


@app.get("/")
def home():
    return send_from_directory("static", "index.html")
@app.get("/dashboard")
def dashboard():
    return send_from_directory("static", "index.html")

@app.get("/health")
def health():
    return jsonify({
        "service": "Bayora API Gateway",
        "status": "healthy",
    })


@app.post("/v1/evaluate")
def evaluate():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A valid JSON object is required."}), 400

    session_id = data.get("session_id")
    scenario = data.get("scenario")
    prompt = data.get("prompt")

    if not isinstance(session_id, str) or session_id not in VALID_SESSIONS:
        return jsonify({"error": "Invalid session ID."}), 400

    if not isinstance(scenario, str) or not scenario.strip():
        return jsonify({"error": "A non-empty scenario is required."}), 400

    if not isinstance(prompt, str) or not prompt.strip():
        return jsonify({"error": "A non-empty prompt is required."}), 400

    if len(prompt) > MAX_PROMPT_LENGTH:
        return jsonify({"error": "Prompt exceeds the 5000-character limit."}), 400

    result = evaluate_scenario(scenario.strip(), prompt)
    decision = result["decision"]

    mock_response = None
    if decision == "ALLOW":
        mock_response = (
            "Demo response: request accepted. "
            "No external AI model is connected."
        )

    ledger.append(
        "EVALUATION_" + decision,
        session_id,
        decision,
        f"{scenario.strip()}: {result['details']}",
    )

    ledger.append(
        "SESSION_CLEANUP",
        session_id,
        "PASS",
        "Demo evaluation state cleared.",
    )

    return jsonify({
        "session_id": session_id,
        "scenario": scenario.strip(),
        "decision": decision,
        "details": result["details"],
        "mock_response": mock_response,
        "cleanup": "complete",
    })


@app.post("/v1/sessions/check")
def check_session_access():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A valid JSON object is required."}), 400

    source_session = data.get("source_session")
    target_session = data.get("target_session")

    if (
        not isinstance(source_session, str)
        or not isinstance(target_session, str)
        or source_session not in VALID_SESSIONS
        or target_session not in VALID_SESSIONS
    ):
        return jsonify({"error": "Invalid source or target session ID."}), 400

    if source_session == target_session:
        decision = "ALLOW"
        details = "Access within the same session is permitted."
    else:
        decision = "BLOCK"
        details = "Cross-session access denied."

    ledger.append(
        "SESSION_ACCESS_" + decision,
        source_session,
        decision,
        f"Source: {source_session}; Target: {target_session}; {details}",
    )

    return jsonify({
        "source_session": source_session,
        "target_session": target_session,
        "decision": decision,
        "details": details,
    })


@app.get("/ledger")
def get_ledger():
    return jsonify({"events": ledger.events})


@app.get("/ledger/verify")
def verify_ledger():
    return jsonify({
        "valid": ledger.verify(),
        "event_count": len(ledger.events),
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
