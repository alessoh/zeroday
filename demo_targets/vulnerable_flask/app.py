"""
Deliberately vulnerable Flask demo application for ZeroDay testing.

This application uses pydantic==1.10.0, which is vulnerable to
CVE-2024-3772 (regular-expression denial-of-service in the
email validator). The vulnerability is reachable via the /register
endpoint, which validates user-supplied email addresses using pydantic's
EmailStr type.

DO NOT use this application in production. It exists solely as a
demonstration target for the ZeroDay CVE Patch Sprinter tool.
"""

from flask import Flask, jsonify, request
from pydantic import BaseModel, EmailStr, ValidationError

app = Flask(__name__)


class UserRegistration(BaseModel):
    username: str
    email: EmailStr  # Validated with pydantic's regex — vulnerable to ReDoS


@app.route("/", methods=["GET"])
def index():
    """Health-check endpoint."""
    return jsonify({"service": "vulnerable-flask-demo", "status": "running"})


@app.route("/register", methods=["POST"])
def register():
    """
    Accept a JSON payload ``{"username": "...", "email": "..."}`` and
    validate it with pydantic.  A maliciously crafted email string can
    trigger catastrophic backtracking in pydantic 1.x's email regex
    (CVE-2024-3772), causing this endpoint to hang.
    """
    body = request.get_json(silent=True) or {}
    try:
        user = UserRegistration(**body)
        return jsonify({"registered": True, "username": user.username})
    except ValidationError as exc:
        return jsonify({"registered": False, "errors": exc.errors()}), 422


@app.route("/ping", methods=["GET"])
def ping():
    """Simple liveness probe."""
    return jsonify({"pong": True})


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
