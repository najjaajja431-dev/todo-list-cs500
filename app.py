import os
from datetime import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///todo.db")


def login_required(f):
    from functools import wraps

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
@login_required
def index():
    user_id = session["user_id"]
    tasks = db.execute("SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC", user_id)
    return render_template("index.html", tasks=tasks)


@app.route("/add", methods=["POST"])
@login_required
def add():
    title = request.form.get("title")
    if title:
        user_id = session["user_id"]
        db.execute(
            "INSERT INTO tasks (user_id, title, done, created_at) VALUES (?, ?, 0, ?)",
            user_id, title, datetime.now().strftime("%Y-%m-%d %H:%M")
        )
    return redirect("/")


@app.route("/toggle/<int:task_id>")
@login_required
def toggle(task_id):
    user_id = session["user_id"]
    task = db.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?", task_id, user_id)
    if task:
        new_status = 0 if task[0]["done"] else 1
        db.execute("UPDATE tasks SET done = ? WHERE id = ?", new_status, task_id)
    return redirect("/")


@app.route("/delete/<int:task_id>")
@login_required
def delete(task_id):
    user_id = session["user_id"]
    db.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", task_id, user_id)
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation:
            flash("Please fill all fields")
            return redirect("/register")

        if password != confirmation:
            flash("Passwords must match")
            return redirect("/register")

        hash = generate_password_hash(password)
        try:
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        except ValueError:
            flash("Username already exists")
            return redirect("/register")

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            flash("Invalid username or password")
            return redirect("/login")

        session["user_id"] = rows[0]["id"]
        return redirect("/")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")
