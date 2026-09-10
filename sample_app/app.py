"""
SAMPLE vulnerable application — for demonstrating the security scan pipeline ONLY.
Deliberately contains common insecure patterns so a scanner has something to find.
Do NOT deploy. Generic example; not a real product.
"""
import hashlib
import os
import sqlite3
import subprocess

# Hardcoded credential (B105/B106) — scanner should flag
DB_PASSWORD = "SuperSecret123!"


def run_report(user_arg):
    # Command executed with shell=True on user input (B602/B605) — injectable
    return subprocess.call("generate_report " + user_arg, shell=True)


def get_user(conn, username):
    # SQL built by string formatting (B608) — injectable
    cur = conn.cursor()
    query = "SELECT * FROM users WHERE name = '%s'" % username
    cur.execute(query)
    return cur.fetchone()


def hash_token(token):
    # Weak hash (B303/B324)
    return hashlib.md5(token.encode()).hexdigest()


def evaluate(expr):
    # Use of eval on caller-supplied text (B307)
    return eval(expr)


def check_admin(role):
    # assert used for a security decision (B101) — stripped under -O
    assert role == "admin"
    return True


def load_config(path):
    # Binds to all interfaces (informational) + reads env password
    host = "0.0.0.0"
    pw = os.environ.get("DB_PASSWORD", DB_PASSWORD)
    return {"host": host, "password": pw, "config": path}


if __name__ == "__main__":
    conn = sqlite3.connect(":memory:")
    print(load_config("/etc/app.conf")["host"])
