from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor
import os

app = Flask(__name__)
app.secret_key = "CHANGE_ME_SUPER_SECRET_KEY"

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=RealDictCursor,
        sslmode="require"
    )

ROLES = [
    "Président Militaire",
    "Président Financier",
    "Chancelier",
    "Ministre Affaires Étrangères",
    "Ministre Intérieur",
    "Ministre Sports",
    "Ministre Éducation",
    "Général",
    "Officier",
    "Soldat",
    "Journaliste",
    "Citoyen"
]

def log_action(username, action):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO logs(username,action) VALUES(%s,%s)",
        (username, action)
    )
    conn.commit()
    conn.close()

def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE,
        password_hash TEXT,
        role TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS news(
        id SERIAL PRIMARY KEY,
        title TEXT,
        content TEXT,
        author TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS announcements(
        id SERIAL PRIMARY KEY,
        title TEXT,
        content TEXT,
        author TEXT,
        visibility TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS military_orders(
        id SERIAL PRIMARY KEY,
        title TEXT,
        content TEXT,
        author TEXT,
        target_role TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id SERIAL PRIMARY KEY,
        username TEXT,
        action TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    defaults = [
        ("president_militaire", "admin123", "Président Militaire"),
        ("president_financier", "admin123", "Président Financier"),
        ("chancelier", "admin123", "Chancelier")
    ]

    for username, password, role in defaults:
        cur.execute(
            "SELECT id FROM users WHERE username=%s",
            (username,)
        )
        existing = cur.fetchone()

        if not existing:
            cur.execute(
                "INSERT INTO users(username,password_hash,role) VALUES(%s,%s,%s)",
                (username, generate_password_hash(password), role)
            )

    conn.commit()
    conn.close()

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return wrapper

def admin_required():
    return session.get("role") in [
        "Président Militaire",
        "Président Financier"
    ]

@app.route("/")
def home():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT * FROM users WHERE username=%s",
            (username,)
        )
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            log_action(user["username"], "Connexion")
            return redirect("/dashboard")

        return "Identifiants incorrects"

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    log_action(session["username"], "Déconnexion")
    session.clear()
    return redirect("/login")

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) c FROM users")
    users = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) c FROM news")
    news = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) c FROM announcements")
    announcements = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) c FROM military_orders")
    orders = cur.fetchone()["c"]

    conn.close()

    stats = {
        "users": users,
        "news": news,
        "announcements": announcements,
        "orders": orders
    }

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        stats=stats
    )

@app.route("/users")
@login_required
def users():
    if not admin_required():
        return "Accès refusé"

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    conn.close()

    return render_template("users.html", users=users)

@app.route("/add_user", methods=["POST"])
@login_required
def add_user():
    if not admin_required():
        return "Accès refusé"

    username = request.form["username"]
    password = request.form["password"]
    role = request.form["role"]

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO users(username,password_hash,role) VALUES(%s,%s,%s)",
        (username, generate_password_hash(password), role)
    )

    conn.commit()
    conn.close()

    log_action(session["username"], f"Création utilisateur {username}")
    return redirect("/users")

@app.route("/delete_user/<int:user_id>")
@login_required
def delete_user(user_id):
    if not admin_required():
        return "Accès refusé"

    conn = get_db()
    cur = conn.cursor()

    cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
    conn.commit()
    conn.close()

    log_action(session["username"], f"Suppression utilisateur {user_id}")
    return redirect("/users")

@app.route("/news")
@login_required
def news():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM news ORDER BY id DESC")
    articles = cur.fetchall()

    conn.close()

    return render_template("news.html", articles=articles)

@app.route("/add_news", methods=["POST"])
@login_required
def add_news():
    if session.get("role") != "Journaliste":
        return "Accès refusé"

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO news(title,content,author) VALUES(%s,%s,%s)",
        (request.form["title"], request.form["content"], session["username"])
    )

    conn.commit()
    conn.close()

    return redirect("/news")

@app.route("/announcements")
@login_required
def announcements():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM announcements ORDER BY id DESC")
    data = cur.fetchall()

    conn.close()

    return render_template("announcements.html", announcements=data)

@app.route("/add_announcement", methods=["POST"])
@login_required
def add_announcement():
    allowed = [
        "Président Militaire",
        "Président Financier",
        "Chancelier",
        "Journaliste"
    ]

    if session.get("role") not in allowed:
        return "Accès refusé"

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO announcements(title,content,author,visibility)
        VALUES(%s,%s,%s,%s)
        """,
        (
            request.form["title"],
            request.form["content"],
            session["username"],
            request.form["visibility"]
        )
    )

    conn.commit()
    conn.close()

    return redirect("/announcements")

@app.route("/military")
@login_required
def military():
    allowed = [
        "Président Militaire",
        "Général",
        "Officier",
        "Soldat"
    ]

    if session.get("role") not in allowed:
        return "Accès refusé"

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM military_orders ORDER BY id DESC")
    orders = cur.fetchall()

    conn.close()

    return render_template("military.html", orders=orders)

@app.route("/add_order", methods=["POST"])
@login_required
def add_order():
    allowed = [
        "Président Militaire",
        "Général",
        "Officier"
    ]

    if session.get("role") not in allowed:
        return "Accès refusé"

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO military_orders(title,content,author,target_role)
        VALUES(%s,%s,%s,%s)
        """,
        (
            request.form["title"],
            request.form["content"],
            session["username"],
            request.form["target_role"]
        )
    )

    conn.commit()
    conn.close()

    return redirect("/military")

@app.route("/logs")
@login_required
def logs():
    if not admin_required():
        return "Accès refusé"

    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 500")
    data = cur.fetchall()

    conn.close()

    return render_template("logs.html", logs=data)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
