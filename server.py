#!/usr/bin/env python3
import csv
import datetime as dt
import json
import os
import smtplib
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from email.message import EmailMessage
from pathlib import Path


def load_env_file(path=".env"):
    env_path = Path(path)
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        raw = line.strip()
        if not raw or raw.startswith("#") or "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


load_env_file()

HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
DATA_DIR = Path("data")
CSV_PATH = DATA_DIR / "discovery_requests.csv"
DISCOVERY_TO = os.getenv("BASECAMP_DISCOVERY_TO", "basecampconsultants@gmail.com")
SMTP_HOST = os.getenv("BASECAMP_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("BASECAMP_SMTP_PORT", "465"))
SMTP_USER = os.getenv("BASECAMP_GMAIL_USER", "")
SMTP_PASS = os.getenv("BASECAMP_GMAIL_APP_PASSWORD", "")


def send_discovery_email(cleaned, timestamp, remote_addr):
    if not SMTP_USER or not SMTP_PASS:
        return False, "SMTP credentials not configured"

    message = EmailMessage()
    message["Subject"] = f"New BASECAMP Discovery Request - {cleaned['full_name']}"
    message["From"] = SMTP_USER
    message["To"] = DISCOVERY_TO
    message.set_content(
        "\n".join(
            [
                "New discovery request received:",
                "",
                f"Submitted At: {timestamp}",
                f"Name: {cleaned['full_name']}",
                f"Email: {cleaned['email']}",
                f"Phone: {cleaned['phone'] or 'Not provided'}",
                f"Goal: {cleaned['goal']}",
                f"Best Call Time: {cleaned['time_window']}",
                f"Remote Address: {remote_addr}",
            ]
        )
    )

    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) as smtp:
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(message)
        return True, "Email sent"
    except Exception as exc:
        return False, f"Email failed: {exc}"


class BasecampHandler(SimpleHTTPRequestHandler):
    def _send_json(self, payload, status=HTTPStatus.OK):
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self):
        if self.path != "/api/discovery":
            self._send_json({"ok": False, "error": "Not found"}, status=HTTPStatus.NOT_FOUND)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json({"ok": False, "error": "Bad request"}, status=HTTPStatus.BAD_REQUEST)
            return

        raw = self.rfile.read(content_length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json({"ok": False, "error": "Invalid JSON"}, status=HTTPStatus.BAD_REQUEST)
            return

        cleaned = {
            "full_name": str(payload.get("fullName", "")).strip(),
            "email": str(payload.get("email", "")).strip(),
            "phone": str(payload.get("phone", "")).strip(),
            "goal": str(payload.get("goal", "")).strip(),
            "time_window": str(payload.get("timeWindow", "")).strip(),
        }

        if not cleaned["full_name"] or not cleaned["email"] or not cleaned["goal"] or not cleaned["time_window"]:
            self._send_json(
                {"ok": False, "error": "Missing required fields"},
                status=HTTPStatus.BAD_REQUEST,
            )
            return

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        write_header = not CSV_PATH.exists()
        timestamp = dt.datetime.now().astimezone().isoformat(timespec="seconds")

        with CSV_PATH.open("a", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            if write_header:
                writer.writerow(
                    [
                        "submitted_at",
                        "full_name",
                        "email",
                        "phone",
                        "goal",
                        "time_window",
                        "remote_addr",
                    ]
                )
            writer.writerow(
                [
                    timestamp,
                    cleaned["full_name"],
                    cleaned["email"],
                    cleaned["phone"],
                    cleaned["goal"],
                    cleaned["time_window"],
                    self.client_address[0],
                ]
            )

        email_ok, email_status = send_discovery_email(cleaned, timestamp, self.client_address[0])
        if not email_ok:
            self._send_json(
                {
                    "ok": False,
                    "error": f"Request saved, but email delivery failed: {email_status}",
                    "email_sent": False,
                    "recipient": DISCOVERY_TO,
                },
                status=HTTPStatus.BAD_GATEWAY,
            )
            return

        self._send_json(
            {
                "ok": True,
                "message": "Request saved and emailed",
                "email_sent": True,
                "email_status": email_status,
                "recipient": DISCOVERY_TO,
            }
        )


def main():
    server = ThreadingHTTPServer((HOST, PORT), BasecampHandler)
    print(f"BASECAMP server running at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
