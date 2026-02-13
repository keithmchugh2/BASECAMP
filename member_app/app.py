import os
import sqlite3
import threading
import time
import smtplib
import ssl
from datetime import datetime
from functools import wraps
from email.message import EmailMessage
from pathlib import Path
from zoneinfo import ZoneInfo

from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "basecamp_app.db"
_reminder_thread_started = False


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = os.getenv("BASECAMP_APP_SECRET", "change-me-in-production")
    app.config["STRIPE_PRICE_ID"] = os.getenv("BASECAMP_STRIPE_PRICE_ID", "")
    app.config["STRIPE_PUBLISHABLE_KEY"] = os.getenv("BASECAMP_STRIPE_PUBLISHABLE_KEY", "")
    app.config["STRIPE_WEBHOOK_SECRET"] = os.getenv("BASECAMP_STRIPE_WEBHOOK_SECRET", "")
    app.config["SMTP_HOST"] = os.getenv("BASECAMP_SMTP_HOST", "smtp.gmail.com")
    app.config["SMTP_PORT"] = int(os.getenv("BASECAMP_SMTP_PORT", "465"))
    app.config["SMTP_USER"] = os.getenv("BASECAMP_SMTP_USER", os.getenv("BASECAMP_GMAIL_USER", ""))
    app.config["SMTP_PASSWORD"] = os.getenv(
        "BASECAMP_SMTP_PASSWORD",
        os.getenv("BASECAMP_GMAIL_APP_PASSWORD", ""),
    )
    app.config["EMAIL_FROM"] = os.getenv("BASECAMP_EMAIL_FROM", app.config["SMTP_USER"] or "no-reply@basecamp.local")

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
        return g.db

    def hash_password(raw_password):
        # Use PBKDF2 for compatibility on environments where hashlib.scrypt is unavailable.
        return generate_password_hash(raw_password, method="pbkdf2:sha256")

    @app.teardown_appcontext
    def close_db(exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    def init_db():
        db = sqlite3.connect(DB_PATH)
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_paid INTEGER NOT NULL DEFAULT 0,
                is_admin INTEGER NOT NULL DEFAULT 0,
                mastermind_opt_in INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS resources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                url TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS workouts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                details TEXT NOT NULL,
                week_label TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS mastermind_posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                details TEXT NOT NULL,
                event_date TEXT,
                location TEXT,
                signup_url TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS daily_tracker_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                entry_date TEXT NOT NULL,
                gratitude TEXT NOT NULL,
                affirmations TEXT NOT NULL,
                intentions TEXT NOT NULL,
                focus TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(user_id, entry_date),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS daily_tracker_settings (
                user_id INTEGER PRIMARY KEY,
                reminder_time TEXT NOT NULL DEFAULT '07:00',
                reminders_enabled INTEGER NOT NULL DEFAULT 1,
                email_reminders_enabled INTEGER NOT NULL DEFAULT 0,
                reminder_timezone TEXT NOT NULL DEFAULT 'UTC',
                last_email_sent_date TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
            """
        )
        columns = {
            row[1] for row in db.execute("PRAGMA table_info(daily_tracker_settings)").fetchall()
        }
        if "email_reminders_enabled" not in columns:
            db.execute(
                "ALTER TABLE daily_tracker_settings ADD COLUMN email_reminders_enabled INTEGER NOT NULL DEFAULT 0"
            )
        if "reminder_timezone" not in columns:
            db.execute(
                "ALTER TABLE daily_tracker_settings ADD COLUMN reminder_timezone TEXT NOT NULL DEFAULT 'UTC'"
            )
        if "last_email_sent_date" not in columns:
            db.execute("ALTER TABLE daily_tracker_settings ADD COLUMN last_email_sent_date TEXT")
        db.commit()

        admin_email = os.getenv("BASECAMP_ADMIN_EMAIL", "admin@basecamp.local")
        admin_password = os.getenv("BASECAMP_ADMIN_PASSWORD", "ChangeThisNow123!")
        now = datetime.utcnow().isoformat(timespec="seconds")

        existing = db.execute("SELECT id FROM users WHERE email = ?", (admin_email,)).fetchone()
        if not existing:
            db.execute(
                """
                INSERT INTO users (full_name, email, password_hash, is_paid, is_admin, mastermind_opt_in, created_at)
                VALUES (?, ?, ?, 1, 1, 1, ?)
                """,
                ("BASECAMP Admin", admin_email, hash_password(admin_password), now),
            )
            db.commit()
        else:
            # Keep admin credentials in sync with Render env vars so you can recover access quickly.
            db.execute(
                """
                UPDATE users
                SET password_hash = ?, is_paid = 1, is_admin = 1
                WHERE email = ?
                """,
                (hash_password(admin_password), admin_email),
            )
            db.commit()
        db.close()

    init_db()

    def send_reminder_email(to_email, full_name):
        smtp_user = app.config["SMTP_USER"]
        smtp_password = app.config["SMTP_PASSWORD"]
        if not smtp_user or not smtp_password:
            return False

        msg = EmailMessage()
        msg["Subject"] = "BASECAMP Daily Tracker Reminder"
        msg["From"] = app.config["EMAIL_FROM"]
        msg["To"] = to_email
        msg.set_content(
            f"""Hi {full_name},

Quick reminder to complete your BASECAMP Daily Tracker:
- Gratitude
- Affirmations
- Intentions
- Today's Focus

Open your member app and lock in your day.

BASECAMP
"""
        )

        try:
            if app.config["SMTP_PORT"] == 465:
                with smtplib.SMTP_SSL(app.config["SMTP_HOST"], app.config["SMTP_PORT"], context=ssl.create_default_context()) as server:
                    server.login(smtp_user, smtp_password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(app.config["SMTP_HOST"], app.config["SMTP_PORT"]) as server:
                    server.starttls(context=ssl.create_default_context())
                    server.login(smtp_user, smtp_password)
                    server.send_message(msg)
            return True
        except Exception:
            return False

    def run_email_reminder_worker():
        while True:
            try:
                db = sqlite3.connect(DB_PATH)
                db.row_factory = sqlite3.Row
                candidates = db.execute(
                    """
                    SELECT
                        users.id AS user_id,
                        users.full_name,
                        users.email,
                        daily_tracker_settings.reminder_time,
                        daily_tracker_settings.reminder_timezone,
                        daily_tracker_settings.last_email_sent_date
                    FROM daily_tracker_settings
                    JOIN users ON users.id = daily_tracker_settings.user_id
                    WHERE daily_tracker_settings.email_reminders_enabled = 1
                    """
                ).fetchall()

                for row in candidates:
                    tz_name = row["reminder_timezone"] or "UTC"
                    try:
                        tz = ZoneInfo(tz_name)
                    except Exception:
                        tz = ZoneInfo("UTC")

                    now_local = datetime.now(tz)
                    today_local = now_local.date().isoformat()
                    reminder_time = (row["reminder_time"] or "07:00").strip()
                    hhmm = now_local.strftime("%H:%M")

                    if hhmm != reminder_time:
                        continue
                    if row["last_email_sent_date"] == today_local:
                        continue

                    entry = db.execute(
                        """
                        SELECT id
                        FROM daily_tracker_entries
                        WHERE user_id = ? AND entry_date = ?
                        """,
                        (row["user_id"], today_local),
                    ).fetchone()
                    if entry:
                        db.execute(
                            """
                            UPDATE daily_tracker_settings
                            SET last_email_sent_date = ?, updated_at = ?
                            WHERE user_id = ?
                            """,
                            (today_local, datetime.utcnow().isoformat(timespec="seconds"), row["user_id"]),
                        )
                        db.commit()
                        continue

                    sent = send_reminder_email(row["email"], row["full_name"])
                    if sent:
                        db.execute(
                            """
                            UPDATE daily_tracker_settings
                            SET last_email_sent_date = ?, updated_at = ?
                            WHERE user_id = ?
                            """,
                            (today_local, datetime.utcnow().isoformat(timespec="seconds"), row["user_id"]),
                        )
                        db.commit()

                db.close()
            except Exception:
                pass

            time.sleep(60)

    def start_reminder_worker_once():
        global _reminder_thread_started
        if _reminder_thread_started:
            return
        _reminder_thread_started = True
        thread = threading.Thread(target=run_email_reminder_worker, daemon=True)
        thread.start()

    start_reminder_worker_once()

    def current_user():
        user_id = session.get("user_id")
        if not user_id:
            return None
        db = get_db()
        return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    @app.context_processor
    def inject_globals():
        return {
            "current_user": current_user(),
            "stripe_publishable_key": app.config["STRIPE_PUBLISHABLE_KEY"],
            "stripe_price_id": app.config["STRIPE_PRICE_ID"],
        }

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user():
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            return fn(*args, **kwargs)

        return wrapper

    def paid_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Please log in first.", "warning")
                return redirect(url_for("login"))
            if not user["is_paid"] and not user["is_admin"]:
                flash("This area is for paying members. Contact Keith to activate your account.", "warning")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)

        return wrapper

    def admin_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user or not user["is_admin"]:
                flash("Admin access required.", "danger")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)

        return wrapper

    @app.get("/")
    def root_redirect():
        return redirect(url_for("dashboard"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if not full_name or not email or not password:
                flash("All fields are required.", "danger")
                return render_template("register.html")

            db = get_db()
            existing = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if existing:
                flash("An account with that email already exists.", "warning")
                return render_template("register.html")

            db.execute(
                """
                INSERT INTO users (full_name, email, password_hash, is_paid, is_admin, mastermind_opt_in, created_at)
                VALUES (?, ?, ?, 0, 0, 0, ?)
                """,
                (full_name, email, hash_password(password), datetime.utcnow().isoformat(timespec="seconds")),
            )
            db.commit()
            flash("Account created. Keith will activate your paid-member access after signup.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if not user or not check_password_hash(user["password_hash"], password):
                flash("Invalid email or password.", "danger")
                return render_template("login.html")
            session["user_id"] = user["id"]
            flash("Welcome back.", "success")
            return redirect(url_for("dashboard"))

        return render_template("login.html")

    @app.get("/logout")
    def logout():
        session.clear()
        flash("Logged out.", "success")
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        user = current_user()
        db = get_db()
        today = datetime.utcnow().date().isoformat()
        my_workouts = db.execute(
            "SELECT id, title, week_label, created_at FROM workouts WHERE user_id = ? ORDER BY id DESC LIMIT 4",
            (user["id"],),
        ).fetchall()
        upcoming_events = db.execute(
            "SELECT id, title, event_date, location FROM events ORDER BY event_date ASC, id DESC LIMIT 4"
        ).fetchall()
        mastermind_count = db.execute("SELECT COUNT(*) AS count FROM mastermind_posts").fetchone()["count"]
        today_tracker = db.execute(
            "SELECT id FROM daily_tracker_entries WHERE user_id = ? AND entry_date = ?",
            (user["id"], today),
        ).fetchone()

        return render_template(
            "dashboard.html",
            my_workouts=my_workouts,
            upcoming_events=upcoming_events,
            mastermind_count=mastermind_count,
            today_tracker_complete=bool(today_tracker),
            today=today,
        )

    @app.route("/daily-tracker", methods=["GET", "POST"])
    @login_required
    def daily_tracker():
        user = current_user()
        db = get_db()
        today = datetime.utcnow().date().isoformat()

        if request.method == "POST":
            action = request.form.get("action", "").strip()
            now = datetime.utcnow().isoformat(timespec="seconds")

            if action == "save_entry":
                entry_date = request.form.get("entry_date", "").strip()
                gratitude = request.form.get("gratitude", "").strip()
                affirmations = request.form.get("affirmations", "").strip()
                intentions = request.form.get("intentions", "").strip()
                focus = request.form.get("focus", "").strip()

                if not entry_date:
                    entry_date = today
                if len(entry_date) != 10:
                    entry_date = today

                if not gratitude or not affirmations or not intentions or not focus:
                    flash("Please complete all 4 sections before saving.", "warning")
                    return redirect(url_for("daily_tracker"))

                db.execute(
                    """
                    INSERT INTO daily_tracker_entries (
                        user_id, entry_date, gratitude, affirmations, intentions, focus, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(user_id, entry_date) DO UPDATE SET
                        gratitude = excluded.gratitude,
                        affirmations = excluded.affirmations,
                        intentions = excluded.intentions,
                        focus = excluded.focus,
                        updated_at = excluded.updated_at
                    """,
                    (user["id"], entry_date, gratitude, affirmations, intentions, focus, now, now),
                )
                db.commit()
                flash("Daily tracker saved.", "success")
                return redirect(url_for("daily_tracker", date=entry_date))

            if action == "save_reminder":
                reminder_time = request.form.get("reminder_time", "07:00").strip()
                reminders_enabled = 1 if request.form.get("reminders_enabled") == "on" else 0
                email_reminders_enabled = 1 if request.form.get("email_reminders_enabled") == "on" else 0
                reminder_timezone = request.form.get("reminder_timezone", "UTC").strip() or "UTC"
                if len(reminder_time) != 5 or ":" not in reminder_time:
                    reminder_time = "07:00"

                db.execute(
                    """
                    INSERT INTO daily_tracker_settings (
                        user_id, reminder_time, reminders_enabled, email_reminders_enabled, reminder_timezone, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        reminder_time = excluded.reminder_time,
                        reminders_enabled = excluded.reminders_enabled,
                        email_reminders_enabled = excluded.email_reminders_enabled,
                        reminder_timezone = excluded.reminder_timezone,
                        updated_at = excluded.updated_at
                    """,
                    (user["id"], reminder_time, reminders_enabled, email_reminders_enabled, reminder_timezone, now),
                )
                db.commit()
                flash("Reminder settings saved.", "success")
                return redirect(url_for("daily_tracker"))

        selected_date = request.args.get("date", today).strip()
        if len(selected_date) != 10:
            selected_date = today

        selected_entry = db.execute(
            """
            SELECT *
            FROM daily_tracker_entries
            WHERE user_id = ? AND entry_date = ?
            """,
            (user["id"], selected_date),
        ).fetchone()

        recent_entries = db.execute(
            """
            SELECT entry_date, gratitude, affirmations, intentions, focus, updated_at
            FROM daily_tracker_entries
            WHERE user_id = ?
            ORDER BY entry_date DESC
            LIMIT 7
            """,
            (user["id"],),
        ).fetchall()

        reminder_settings = db.execute(
            """
            SELECT reminder_time, reminders_enabled, email_reminders_enabled, reminder_timezone
            FROM daily_tracker_settings
            WHERE user_id = ?
            """,
            (user["id"],),
        ).fetchone()

        reminder_time = reminder_settings["reminder_time"] if reminder_settings else "07:00"
        reminders_enabled = reminder_settings["reminders_enabled"] if reminder_settings else 1
        email_reminders_enabled = reminder_settings["email_reminders_enabled"] if reminder_settings else 0
        reminder_timezone = reminder_settings["reminder_timezone"] if reminder_settings else "UTC"

        today_entry = db.execute(
            "SELECT id FROM daily_tracker_entries WHERE user_id = ? AND entry_date = ?",
            (user["id"], today),
        ).fetchone()

        return render_template(
            "daily_tracker.html",
            selected_date=selected_date,
            selected_entry=selected_entry,
            recent_entries=recent_entries,
            reminder_time=reminder_time,
            reminders_enabled=bool(reminders_enabled),
            email_reminders_enabled=bool(email_reminders_enabled),
            reminder_timezone=reminder_timezone,
            today=today,
            today_complete=bool(today_entry),
        )

    @app.get("/resources")
    @paid_required
    def resources():
        db = get_db()
        items = db.execute("SELECT * FROM resources ORDER BY id DESC").fetchall()
        return render_template("resources.html", items=items)

    @app.get("/workouts")
    @paid_required
    def workouts():
        user = current_user()
        db = get_db()
        items = db.execute(
            "SELECT * FROM workouts WHERE user_id = ? ORDER BY id DESC",
            (user["id"],),
        ).fetchall()
        return render_template("workouts.html", items=items)

    @app.route("/mastermind", methods=["GET", "POST"])
    @paid_required
    def mastermind():
        user = current_user()
        db = get_db()

        if request.method == "POST":
            action = request.form.get("action")
            if action == "opt_in":
                db.execute("UPDATE users SET mastermind_opt_in = 1 WHERE id = ?", (user["id"],))
                db.commit()
                flash("You are now opted in to Mastermind.", "success")
                return redirect(url_for("mastermind"))

            if action == "post" and user["mastermind_opt_in"]:
                content = request.form.get("content", "").strip()
                if content:
                    db.execute(
                        "INSERT INTO mastermind_posts (user_id, content, created_at) VALUES (?, ?, ?)",
                        (user["id"], content, datetime.utcnow().isoformat(timespec="seconds")),
                    )
                    db.commit()
                    flash("Posted to the Mastermind group.", "success")
                else:
                    flash("Post cannot be empty.", "warning")
                return redirect(url_for("mastermind"))

        user = current_user()
        posts = db.execute(
            """
            SELECT mastermind_posts.*, users.full_name
            FROM mastermind_posts
            JOIN users ON users.id = mastermind_posts.user_id
            ORDER BY mastermind_posts.id DESC
            LIMIT 50
            """
        ).fetchall()
        return render_template("mastermind.html", posts=posts)

    @app.get("/events")
    @paid_required
    def events():
        db = get_db()
        items = db.execute("SELECT * FROM events ORDER BY event_date ASC, id DESC").fetchall()
        return render_template("events.html", items=items)

    @app.get("/billing")
    @login_required
    def billing():
        return render_template("billing.html")

    @app.route("/admin", methods=["GET", "POST"])
    @admin_required
    def admin():
        db = get_db()
        if request.method == "POST":
            form_type = request.form.get("form_type")

            if form_type == "member_status":
                user_id = request.form.get("user_id", type=int)
                is_paid = 1 if request.form.get("is_paid") == "on" else 0
                is_admin = 1 if request.form.get("is_admin") == "on" else 0
                db.execute("UPDATE users SET is_paid = ?, is_admin = ? WHERE id = ?", (is_paid, is_admin, user_id))
                db.commit()
                flash("Member status updated.", "success")

            elif form_type == "resource":
                title = request.form.get("title", "").strip()
                description = request.form.get("description", "").strip()
                url = request.form.get("url", "").strip()
                if title and url:
                    db.execute(
                        "INSERT INTO resources (title, description, url, created_at) VALUES (?, ?, ?, ?)",
                        (title, description, url, datetime.utcnow().isoformat(timespec="seconds")),
                    )
                    db.commit()
                    flash("Resource added.", "success")
                else:
                    flash("Resource title and URL are required.", "warning")

            elif form_type == "workout":
                title = request.form.get("title", "").strip()
                details = request.form.get("details", "").strip()
                week_label = request.form.get("week_label", "").strip()
                target_user = request.form.get("target_user", "").strip()
                now = datetime.utcnow().isoformat(timespec="seconds")

                if not title or not details:
                    flash("Workout title and details are required.", "warning")
                else:
                    if target_user == "ALL_PAID":
                        paid_users = db.execute("SELECT id FROM users WHERE is_paid = 1").fetchall()
                        for u in paid_users:
                            db.execute(
                                "INSERT INTO workouts (user_id, title, details, week_label, created_at) VALUES (?, ?, ?, ?, ?)",
                                (u["id"], title, details, week_label, now),
                            )
                        db.commit()
                        flash(f"Workout sent to {len(paid_users)} paid members.", "success")
                    else:
                        db.execute(
                            "INSERT INTO workouts (user_id, title, details, week_label, created_at) VALUES (?, ?, ?, ?, ?)",
                            (int(target_user), title, details, week_label, now),
                        )
                        db.commit()
                        flash("Workout assigned.", "success")

            elif form_type == "event":
                title = request.form.get("title", "").strip()
                details = request.form.get("details", "").strip()
                event_date = request.form.get("event_date", "").strip()
                location = request.form.get("location", "").strip()
                signup_url = request.form.get("signup_url", "").strip()

                if title and details:
                    db.execute(
                        """
                        INSERT INTO events (title, details, event_date, location, signup_url, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (title, details, event_date, location, signup_url, datetime.utcnow().isoformat(timespec="seconds")),
                    )
                    db.commit()
                    flash("Event published.", "success")
                else:
                    flash("Event title and details are required.", "warning")

            return redirect(url_for("admin"))

        users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        resources = db.execute("SELECT * FROM resources ORDER BY id DESC LIMIT 10").fetchall()
        events = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT 10").fetchall()
        return render_template("admin.html", users=users, resources=resources, events=events)

    @app.post("/webhooks/stripe")
    def stripe_webhook():
        # Stripe wiring point: validate signature + map Stripe customer/email to user + set is_paid=1.
        # Kept as stub for now because live Stripe secret and webhook signing key are environment-specific.
        return {"ok": True, "message": "Stripe webhook endpoint is ready for integration."}

    @app.route("/bootstrap/reset-admin", methods=["GET", "POST"])
    def bootstrap_reset_admin():
        setup_key = os.getenv("BASECAMP_SETUP_KEY", "")
        provided_key = request.args.get("key", "")
        if not setup_key or provided_key != setup_key:
            return {"ok": False, "error": "Unauthorized"}, 401

        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            if not email or not password:
                flash("Email and password are required.", "warning")
                return render_template("bootstrap_reset_admin.html")

            db = get_db()
            user = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            now = datetime.utcnow().isoformat(timespec="seconds")
            if user:
                db.execute(
                    """
                    UPDATE users
                    SET password_hash = ?, is_paid = 1, is_admin = 1
                    WHERE email = ?
                    """,
                    (hash_password(password), email),
                )
            else:
                db.execute(
                    """
                    INSERT INTO users (full_name, email, password_hash, is_paid, is_admin, mastermind_opt_in, created_at)
                    VALUES (?, ?, ?, 1, 1, 1, ?)
                    """,
                    ("BASECAMP Admin", email, hash_password(password), now),
                )
            db.commit()
            flash("Admin credentials reset. You can now log in.", "success")
            return redirect(url_for("login"))

        return render_template("bootstrap_reset_admin.html")

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
