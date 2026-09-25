import hashlib
import hmac
import os
import secrets
from datetime import datetime
from typing import Any, Dict, List

import requests
from flask import Flask, request, jsonify


app = Flask(__name__)

SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
WEBHOOK_API_KEY = os.environ.get("WEBHOOK_API_KEY")

def is_authorized_request() -> bool:
    if not WEBHOOK_API_KEY:
        return False

    provided_hmac = request.headers.get("X-Sonar-Webhook-HMAC-SHA256")

    if not provided_hmac:
        return False

    computed_hmac = hmac.new(
        WEBHOOK_API_KEY.encode("utf-8"),
        request.get_data(),
        hashlib.sha256,
    ).hexdigest()

    return secrets.compare_digest(provided_hmac, computed_hmac)

def parse_sonarqube_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    project = payload.get("project", {})
    quality_gate = payload.get("qualityGate", {})

    conditions = quality_gate.get("conditions", [])
    failed_conditions = [
        condition for condition in conditions
        if condition.get("status") not in ("OK", "NO_VALUE")
    ]

    analysed_at = payload.get("analysedAt")
    formatted_analysed_at = analysed_at

    if analysed_at:
        try:
            parsed_date = datetime.strptime(analysed_at, "%Y-%m-%dT%H:%M:%S%z")
            formatted_analysed_at = parsed_date.strftime("%Y-%m-%d %H:%M:%S %Z")
        except ValueError:
            pass

    return {
        "server_url": payload.get("serverUrl"),
        "task_id": payload.get("taskId"),
        "analysis_status": payload.get("status"),
        "analysed_at": formatted_analysed_at,
        "revision": payload.get("revision"),
        "project_key": project.get("key"),
        "project_name": project.get("name"),
        "project_url": project.get("url"),
        "quality_gate_name": quality_gate.get("name"),
        "quality_gate_status": quality_gate.get("status"),
        "conditions": conditions,
        "failed_conditions": failed_conditions,
    }


def get_status_emoji(status: str) -> str:
    if status == "OK":
        return ":white_check_mark:"
    if status == "ERROR":
        return ":x:"
    if status == "WARN":
        return ":warning:"
    return ":grey_question:"


def format_condition(condition: Dict[str, Any]) -> str:
    metric = condition.get("metric", "unknown_metric")
    status = condition.get("status", "UNKNOWN")
    operator = condition.get("operator", "")
    value = condition.get("value", "N/A")
    threshold = condition.get("errorThreshold", "N/A")
    on_leak_period = condition.get("onLeakPeriod", False)

    leak_period_label = "new code" if on_leak_period else "overall code"

    return (
        f"• `{metric}` on *{leak_period_label}*: "
        f"*{status}* — value `{value}`, rule `{operator} {threshold}`"
    )


def build_slack_message(parsed: Dict[str, Any]) -> Dict[str, Any]:
    quality_gate_status = parsed.get("quality_gate_status", "UNKNOWN")
    emoji = get_status_emoji(quality_gate_status)

    project_name = parsed.get("project_name") or parsed.get("project_key") or "Unknown Project"
    project_url = parsed.get("project_url")

    if project_url:
        project_text = f"<{project_url}|{project_name}>"
    else:
        project_text = project_name

    color = {
        "OK": "good",
        "WARN": "warning",
        "ERROR": "danger",
    }.get(quality_gate_status, "#808080")

    conditions: List[Dict[str, Any]] = parsed.get("conditions", [])
    failed_conditions: List[Dict[str, Any]] = parsed.get("failed_conditions", [])

    if failed_conditions:
        condition_text = "\n".join(format_condition(condition) for condition in failed_conditions)
    elif conditions:
        condition_text = "All quality gate conditions passed."
    else:
        condition_text = "No quality gate conditions were provided."

    return {
        "text": f"{emoji} SonarQube Quality Gate: {quality_gate_status} for {project_name}",
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{emoji} SonarQube Quality Gate: {quality_gate_status}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Project:*\n{project_text}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Quality Gate:*\n{parsed.get('quality_gate_name', 'Unknown')}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Analysis Status:*\n{parsed.get('analysis_status', 'Unknown')}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Analysed At:*\n{parsed.get('analysed_at', 'Unknown')}",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Project Key:*\n`{parsed.get('project_key', 'Unknown')}`",
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Revision:*\n`{parsed.get('revision', 'Unknown')}`",
                            },
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Conditions:*\n{condition_text}",
                        },
                    },
                ],
            }
        ],
    }


def send_slack_notification(message: Dict[str, Any]) -> None:
    if not SLACK_WEBHOOK_URL:
        raise RuntimeError("SLACK_WEBHOOK_URL environment variable is not set")

    response = requests.post(
        SLACK_WEBHOOK_URL,
        json=message,
        timeout=10,
    )

    response.raise_for_status()


@app.route("/sonarqube-webhook", methods=["POST"])
def sonarqube_webhook():
    if not is_authorized_request():
        return jsonify({"error": "Forbidden"}), 403

    payload = request.get_json(silent=True)

    if not payload:
        return jsonify({"error": "Invalid or empty JSON payload"}), 400

    try:
        parsed_payload = parse_sonarqube_payload(payload)
        slack_message = build_slack_message(parsed_payload)
        send_slack_notification(slack_message)
    except requests.HTTPError as exc:
        return jsonify({
            "error": "Failed to send Slack notification",
            "details": str(exc),
        }), 502
    except Exception as exc:
        return jsonify({
            "error": "Unexpected error processing webhook",
            "details": str(exc),
        }), 500

    return jsonify({"status": "notification_sent"}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

@app.route("/", methods=["GET"])
def root():
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
