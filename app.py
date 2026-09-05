from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, re

app = Flask(__name__)
app.secret_key = "change-this-secret-key"

DB = "users.db"

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )""")

def valid_username(username):
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,30}", username or ""))

@app.route("/")
def home():
    return render_template("index.html", username=session.get("username"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not valid_username(username):
            flash("Username must be 3-30 characters using letters, numbers or _.")
            return redirect(url_for("register"))
        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("register"))
        try:
            with sqlite3.connect(DB) as con:
                con.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
                            (username, generate_password_hash(password)))
            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with sqlite3.connect(DB) as con:
            row = con.execute("SELECT username,password_hash FROM users WHERE username=?",
                              (username,)).fetchone()
        if row and check_password_hash(row[1], password):
            session.clear()
            session["username"] = row[0]
            return redirect(url_for("home"))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8501, debug=False)
