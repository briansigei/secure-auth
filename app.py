
import sqlite3
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
bcrypt = Bcrypt(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]
)

DB = "users.db"


def connect_db():
    return sqlite3.connect(DB)


def setup_db():
    with connect_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        """)


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not isinstance(password, str):
        return jsonify(error="Username and password required"), 400

    if len(password) < 12:
        return jsonify(error="Password must be at least 12 characters"), 400

    password_hash = bcrypt.generate_password_hash(
        password
    ).decode("utf-8")

    try:
        with connect_db() as db:
            db.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
        return jsonify(message="User registered"), 201

    except sqlite3.IntegrityError:
        return jsonify(error="Username already exists"), 409


@app.post("/login")
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    with connect_db() as db:
        user = db.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if user and bcrypt.check_password_hash(user[0], password):
        return jsonify(message="Login successful"), 200

    return jsonify(error="Invalid username or password"), 401


if __name__ == "__main__":
    setup_db()
    app.run(debug=True)
