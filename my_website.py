
import os

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from database import get_postgres_user


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
        username=user[1]
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


if __name__ == "__main__":
    app.run(debug=True)
