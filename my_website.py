import os
import json
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Use Render environment variables if available.
# Otherwise, load the local configuration file.

if os.environ.get("SECRET_KEY"):
    config = {
        "username": os.environ["LOGIN_USERNAME"],
        "password_hash": os.environ["LOGIN_PASSWORD_HASH"],
        "secret_key": os.environ["SECRET_KEY"]
    }
else:
    config_path = Path(__file__).parent / "login_config.json"

    with open(config_path, "r") as file:
        config = json.load(file)

app.secret_key = config["secret_key"]


@app.route("/")
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if (
            username == config["username"]
            and check_password_hash(config["password_hash"], password)
        ):
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Invalid username or password"
        )

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
