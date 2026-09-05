from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, re, os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL)""")

init_db()

def valid_username(u):
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,30}", u or ""))

@app.route("/")
def home():
    return render_template("index.html", username=session.get("username"))

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        u=request.form.get("username","").strip(); p=request.form.get("password","")
        if not valid_username(u): flash("Username must be 3-30 characters using letters, numbers or _."); return redirect(url_for("register"))
        if len(p)<8: flash("Password must contain at least 8 characters."); return redirect(url_for("register"))
        try:
            with sqlite3.connect(DB) as con:
                con.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",(u,generate_password_hash(p)))
            flash("Registration successful. Please log in."); return redirect(url_for("login"))
        except sqlite3.IntegrityError: flash("Username already exists.")
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=request.form.get("username","").strip(); p=request.form.get("password","")
        with sqlite3.connect(DB) as con:
            row=con.execute("SELECT username,password_hash FROM users WHERE username=?",(u,)).fetchone()
        if row and check_password_hash(row[1],p):
            session.clear(); session["username"]=row[0]; return redirect(url_for("home"))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear(); flash("You have been logged out."); return redirect(url_for("home"))

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",8501)))
