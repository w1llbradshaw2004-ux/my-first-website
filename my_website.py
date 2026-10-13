
import os

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import check_password_hash
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from database import (
    get_postgres_user,
    get_postgres_user_by_id,
    get_all_users,
    create_managed_user,
    send_message,
    get_messages,
    delete_message
)


# Load local environment variables
load_dotenv()

# Initialize Flask
app = Flask(__name__)

app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER") == "true"
)


# Trust Render's forwarding proxy in production
if os.environ.get("RENDER") == "true":
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,
        x_proto=1
    )


csrf = CSRFProtect(app)

@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    session.clear()
    return redirect(url_for("login"))

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
)


@app.route("/")
def home():
    """Display the homepage for authenticated users."""

    if "user_id" not in session:
        return redirect(url_for("login"))

    # Verify the account still exists
    user = get_postgres_user(session.get("username", ""))

    if not user or user[0] != session["user_id"]:
        session.clear()
        return redirect(url_for("login"))

    return render_template(
    "index.html",
    username=user[1],
    is_admin=user[3] == "admin"
    )


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    """Authenticate users against PostgreSQL."""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Retrieve the user from Supabase
        user = get_postgres_user(username)

        if user and check_password_hash(user[2], password):
            session.clear()

            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[3]

            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    """Log out the current user."""

    session.clear()
    return redirect(url_for("login"))



@app.route("/admin", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def admin():
    """Admin dashboard for managing user accounts."""

    user_id = session.get("user_id")

    if user_id is None:
        return redirect(url_for("login"))

    # Always check the current database role.
    # Never trust a previously saved session role.
    current_user = get_postgres_user_by_id(user_id)

    if not current_user:
        session.clear()
        return redirect(url_for("login"))

    if current_user[3] != "admin":
        return "Access denied", 403

    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not (
            3 <= len(username) <= 32
            and username.isascii()
            and all(c.isalnum() or c == "_" for c in username)
        ):
            error = "Username must be 3-32 letters, numbers, or underscores."

        elif not 12 <= len(password) <= 128:
            error = "Password must be between 12 and 128 characters."

        else:
            created = create_managed_user(username, password)

            if created:
                success = f"Account '{username}' created successfully."
            else:
                error = "That username already exists."

    users = get_all_users()

    return render_template(
        "admin.html",
        users=users,
        error=error,
        success=success
    )


@app.route("/chat")
def chat():
    """Display the group chat page."""

    user_id = session.get("user_id")

    if user_id is None:
        return redirect(url_for("login"))

    user = get_postgres_user_by_id(user_id)

    if not user:
        session.clear()
        return redirect(url_for("login"))

    return render_template(
    "chat.html",
    username=user[1],
    is_admin=user[3] == "admin"
    )


@app.route("/api/messages", methods=["GET"])
@limiter.limit("40 per minute")
def api_get_messages():
    """Return the latest unexpired messages as JSON."""

    user_id = session.get("user_id")

    if user_id is None:
        return jsonify({"error": "Unauthorized"}), 401

    user = get_postgres_user_by_id(user_id)

    if not user:
        session.clear()
        return jsonify({"error": "Unauthorized"}), 401

    messages = get_messages()

    result = []

    for message in messages:
        result.append({
            "id": message[0],
            "username": message[1],
            "content": message[2],
            "created_at": message[3].isoformat()
        })

    return jsonify(result)


@app.route("/api/messages", methods=["POST"])
@limiter.limit("10 per minute")
def api_send_message():
    """Save a message from an authenticated user."""

    user_id = session.get("user_id")

    if user_id is None:
        return jsonify({"error": "Unauthorized"}), 401

    user = get_postgres_user_by_id(user_id)

    if not user:
        session.clear()
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400

    content = data.get("content", "")

    if not isinstance(content, str):
        return jsonify({"error": "Message must be text"}), 400

    try:
        message_id = send_message(user_id, content)

    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    return jsonify({
        "success": True,
        "message_id": message_id
    }), 201



@app.route("/api/messages/<int:message_id>/delete", methods=["POST"])
@limiter.limit("20 per minute")
def api_delete_message(message_id):
    """Allow administrators to delete chat messages."""

    user_id = session.get("user_id")

    if user_id is None:
        return jsonify({"error": "Unauthorized"}), 401

    # Retrieve the current user from PostgreSQL
    user = get_postgres_user_by_id(user_id)

    if not user:
        session.clear()
        return jsonify({"error": "Unauthorized"}), 401

    # Only administrators may delete messages
    if user[3] != "admin":
        return jsonify({"error": "Access denied"}), 403

    deleted = delete_message(message_id)

    if not deleted:
        return jsonify({"error": "Message not found"}), 404

    return jsonify({
        "success": True,
        "message": "Message deleted successfully"
    })



if __name__ == "__main__":
    app.run(debug=True)
