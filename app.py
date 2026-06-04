import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "gb-dashboard-secret-2026-change-me")

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access the dashboard."

# ── DATABASE ─────────────────────────────────────────────────────────────────

def get_db():
    return psycopg2.connect(os.environ["DATABASE_URL"], sslmode="require")

def init_db():
    """Create users table and default admin if needed."""
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username  TEXT PRIMARY KEY,
                    name      TEXT NOT NULL,
                    password  TEXT NOT NULL,
                    role      TEXT NOT NULL DEFAULT 'staff',
                    email     TEXT DEFAULT ''
                )
            """)
            # Create default admin only if table is empty
            cur.execute("SELECT COUNT(*) FROM users")
            count = cur.fetchone()[0]
            if count == 0:
                cur.execute(
                    "INSERT INTO users (username, name, password, role, email) VALUES (%s,%s,%s,%s,%s)",
                    ("admin", "Admin", generate_password_hash("GreenBros2026!"), "admin", "admin@greenbros.co.uk")
                )
                print("Default admin created. Username: admin  Password: GreenBros2026!")
        conn.commit()

# ── USER MODEL ────────────────────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, row):
        self.id    = row["username"]
        self.name  = row["name"]
        self.role  = row["role"]
        self.email = row["email"] or ""

def get_user(username):
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
    return User(row) if row else None

def get_all_users():
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT username, name, role, email FROM users ORDER BY role DESC, username")
            return cur.fetchall()

@login_manager.user_loader
def load_user(user_id):
    return get_user(user_id)

# ── ROUTES ────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    users = get_all_users()
    user_count  = len(users)
    admin_count = sum(1 for u in users if u["role"] == "admin")
    staff_count = user_count - admin_count
    return render_template("dashboard.html", user=current_user,
                           user_count=user_count,
                           admin_count=admin_count,
                           staff_count=staff_count)

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        with get_db() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM users WHERE username = %s", (username,))
                row = cur.fetchone()
        if row and check_password_hash(row["password"], password):
            login_user(User(row), remember=request.form.get("remember"))
            return redirect(request.args.get("next") or url_for("index"))
        flash("Invalid username or password.")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ── ADMIN ROUTES ──────────────────────────────────────────────────────────────

@app.route("/admin/users")
@login_required
def admin_users():
    if current_user.role != "admin":
        flash("Admin access required.", "error")
        return redirect(url_for("index"))
    users = get_all_users()
    return render_template("admin_users.html", users=users, user=current_user)

@app.route("/admin/users/add", methods=["POST"])
@login_required
def add_user():
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    data     = request.json
    username = data.get("username", "").strip().lower()
    name     = data.get("name", "").strip()
    password = data.get("password", "")
    role     = data.get("role", "staff")
    email    = data.get("email", "").strip()

    if not username or not name or not password:
        return jsonify({"error": "Username, name and password are required."}), 400

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (username, name, password, role, email) VALUES (%s,%s,%s,%s,%s)",
                    (username, name, generate_password_hash(password), role, email)
                )
            conn.commit()
    except psycopg2.errors.UniqueViolation:
        return jsonify({"error": "Username already exists."}), 400

    return jsonify({"ok": True})

@app.route("/admin/users/delete", methods=["POST"])
@login_required
def delete_user():
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    username = request.json.get("username", "")
    if username == current_user.id:
        return jsonify({"error": "You cannot delete your own account."}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username = %s", (username,))
        conn.commit()
    return jsonify({"ok": True})

@app.route("/admin/users/reset-password", methods=["POST"])
@login_required
def reset_password():
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    data     = request.json
    username = data.get("username", "")
    password = data.get("password", "")
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET password = %s WHERE username = %s",
                (generate_password_hash(password), username)
            )
        conn.commit()
    return jsonify({"ok": True})

@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    data = request.json
    uid  = current_user.id
    with get_db() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT password FROM users WHERE username = %s", (uid,))
            row = cur.fetchone()
    if not row or not check_password_hash(row["password"], data.get("current", "")):
        return jsonify({"error": "Current password is incorrect."}), 400
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET password = %s WHERE username = %s",
                (generate_password_hash(data["new"]), uid)
            )
        conn.commit()
    return jsonify({"ok": True})

@app.route("/admin/users-json")
@login_required
def admin_users_json():
    if current_user.role != "admin":
        return jsonify({"error": "Unauthorized"}), 403
    users = get_all_users()
    return jsonify([dict(u) for u in users])

# ── STARTUP ───────────────────────────────────────────────────────────────────

init_db()

if __name__ == "__main__":
    app.run(debug=True)

@app.route("/overview")
@login_required
def overview():
    return render_template("overview.html", user=current_user)
