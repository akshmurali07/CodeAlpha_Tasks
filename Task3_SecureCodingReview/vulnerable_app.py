from flask import Flask, request, render_template_string
import sqlite3
import hashlib
import os

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded Credentials
SECRET_KEY = "admin123"
DB_PASSWORD = "password123"
ADMIN_USER = "admin"
ADMIN_PASS = "admin123"

# VULNERABILITY 2: Weak password hashing (MD5)
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def get_db():
    conn = sqlite3.connect("users.db")
    return conn

def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users
                    (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)""")
    conn.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@site.com')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2, 'alice', 'alice123', 'alice@site.com')")
    conn.commit()
    conn.close()

# VULNERABILITY 3: SQL Injection
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db()
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        result = conn.execute(query).fetchone()
        conn.close()
        if result:
            return f"Welcome {username}!"
        else:
            error = "Invalid credentials"
    return render_template_string("""
        <form method='post'>
            Username: <input name='username'><br>
            Password: <input name='password' type='password'><br>
            <input type='submit' value='Login'>
            <p style='color:red'>{{ error }}</p>
        </form>
    """, error=error)

# VULNERABILITY 4: Cross-Site Scripting (XSS)
@app.route("/search")
def search():
    query = request.args.get("q", "")
    return f"<h2>Search results for: {query}</h2>"

# VULNERABILITY 5: Path Traversal
@app.route("/file")
def read_file():
    filename = request.args.get("name", "")
    filepath = os.path.join("uploads", filename)
    try:
        with open(filepath, "r") as f:
            return f.read()
    except:
        return "File not found"

# VULNERABILITY 6: Sensitive Data Exposure
@app.route("/users")
def list_users():
    conn = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return str(users)

# VULNERABILITY 7: Debug Mode Enabled
if __name__ == "__main__":
    init_db()
    app.run(debug=True)