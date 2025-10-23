# app.py
from flask import Flask, request, jsonify, g, render_template_string
import sqlite3
import os
import pickle
import base64
import requests
import xml.etree.ElementTree as ET

DB = "/data/demo.db"
app = Flask(__name__)

# Hardcoded credentials (exposed)
app.config["SECRET_KEY"] = "super-secret-key-that-should-not-be-in-code"
app.config["GITHUB_API_TOKEN"] = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"

def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = sqlite3.connect(DB)
        g._db = db
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db:
        db.close()

@app.route("/")
def index():
    return "SQLi, XSS, RCE, LFI, SSRF, Path Traversal, XXE, IDOR, Weak Auth demo app"

# ... (existing vulnerable endpoints) ...

# Weak authentication endpoint
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    # Weak authentication - using string concatenation and hardcoded credentials
    sql = "SELECT id FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    try:
        cur = get_db().execute(sql)
        row = cur.fetchone()
        if row:
            # Insecure session management
            return jsonify({"status": "success", "user_id": row[0], "token": "weak-token-" + str(row[0])})
        else:
            # Information disclosure - reveals if username exists
            return jsonify({"status": "failed", "message": "Invalid username or password"}), 401
    except Exception as e:
        return jsonify({"error": "db error", "msg": str(e)}), 500

# Vulnerable GET endpoint: user id in query string used unsafely (SQLi)
@app.route("/user")
def get_user():
    user_id = request.args.get("id", "")
    # Intentional insecure string concatenation (vulnerable to SQLi)
    sql = f"SELECT id, username, email FROM users WHERE id = {user_id}"
    try:
        cur = get_db().execute(sql)
        row = cur.fetchone()
        if row:
            return jsonify({"id": row[0], "username": row[1], "email": row[2]})
        return jsonify({"error": "not found"}), 404
    except Exception as e:
        # Return DB error text intentionally (helps detection in test)
        return jsonify({"error": "db error", "msg": str(e)}), 500

# IDOR vulnerability - direct access to user data without authorization check
@app.route("/api/user/<int:user_id>")
def api_user(user_id):
    # No access control check - any user can access any other user's data
    sql = "SELECT id, username, email FROM users WHERE id = ?"
    try:
        cur = get_db().execute(sql, (user_id,))
        row = cur.fetchone()
        if row:
            return jsonify({"id": row[0], "username": row[1], "email": row[2]})
        return jsonify({"error": "not found"}), 404
    except Exception as e:
        return jsonify({"error": "db error", "msg": str(e)}), 500

# Vulnerable POST endpoint: form-encoded (SQLi)
@app.route("/search", methods=["POST"])
def search_user():
    q = request.form.get("q", "")
    sql = "SELECT id, username FROM users WHERE username LIKE '_" + q + "_%'"
    try:
        cur = get_db().execute(sql)
        rows = cur.fetchall()
        return jsonify([{"id": r[0], "username": r[1]} for r in rows])
    except Exception as e:
        return jsonify({"error": "db error", "msg": str(e)}), 500

# Vulnerable JSON endpoint (SQLi)
@app.route("/api/users", methods=["POST"])
def api_users():
    body = request.get_json(silent=True) or {}
    email = body.get("email", "")
    sql = f"SELECT id, username, email FROM users WHERE email = '{email}'"
    try:
        cur = get_db().execute(sql)
        row = cur.fetchone()
        if row:
            return jsonify({"id": row[0], "username": row[1], "email": row[2]})
        return jsonify({"error": "not found"}), 404
    except Exception as e:
        return jsonify({"error": "db error", "msg": str(e)}), 500

# Command Injection vulnerability
@app.route("/tools/dns-lookup")
def dns_lookup():
    host = request.args.get("host", "")
    # Insecure use of os.system (vulnerable to command injection)
    cmd = f"nslookup {host}"
    stream = os.popen(cmd)
    output = stream.read()
    return output, 200, {"Content-Type": "text/plain"}

# XXE Injection vulnerability
@app.route("/xxe", methods=["POST"])
def xxe():
    try:
        # Parse XML without disabling external entities
        tree = ET.fromstring(request.data)
        # Process XML data
        result = ET.tostring(tree, encoding='unicode')
        return result, 200, {"Content-Type": "application/xml"}
    except Exception as e:
        return f"<error>{str(e)}</error>", 500, {"Content-Type": "application/xml"}

# XSS vulnerability
@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    # Insecurely rendering user input (vulnerable to XSS)
    return render_template_string(f"<h1>Hello, {name}!</h1>")

# Insecure Deserialization vulnerability
@app.route("/pickle", methods=["POST"])
def load_pickle():
    try:
        data = base64.b64decode(request.data)
        # Insecure deserialization of user-provided data
        deserialized_data = pickle.loads(data)
        return jsonify({"status": "ok", "data": str(deserialized_data)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# SSRF vulnerability
@app.route("/proxy")
def proxy():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "url parameter is missing"}), 400
    try:
        # Insecure request to a user-provided URL (vulnerable to SSRF)
        r = requests.get(url)
        return r.text, r.status_code, r.headers.items()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Local File Inclusion (LFI) vulnerability
@app.route("/page")
def page():
    page = request.args.get("p", "index.html")
    try:
        # Insecurely including a file from the filesystem
        with open(os.path.join("/app/pages", page)) as f:
            return f.read()
    except Exception as e:
        return str(e), 404

# Path Traversal vulnerability
@app.route("/files")
def files():
    filename = request.args.get("filename", "")
    try:
        # Vulnerable to path traversal attacks
        with open(filename, "r") as f:
            return f.read()
    except Exception as e:
        return str(e), 404

# New Endpoints

# Get all products
@app.route("/products", methods=["GET"])
def get_products():
    try:
        cur = get_db().execute("SELECT * FROM products")
        rows = cur.fetchall()
        return jsonify([{"id": r[0], "name": r[1], "description": r[2], "price": r[3]} for r in rows])
    except Exception as e:
        return jsonify({"error": "db error", "msg": str(e)}), 500

# Search for a product (SQLi)
@app.route("/products/search", methods=["GET"])
def search_products():
    name = request.args.get("name", "")
    sql = f"SELECT * FROM products WHERE name LIKE '%{name}%'"
    try:
        cur = get_db().execute(sql)
        rows = cur.fetchall()
        return jsonify([{"id": r[0], "name": r[1], "description": r[2], "price": r[3]} for r in rows])
    except Exception as e:
        return jsonify({"error": "db error", "msg": str(e)}), 500

# Get a specific product (SQLi)
@app.route("/products/<product_id>", methods=["GET"])
def get_product(product_id):
    sql = f"SELECT * FROM products WHERE id = {product_id}"
    try:
        cur = get_db().execute(sql)
        row = cur.fetchone()
        if row:
            return jsonify({"id": row[0], "name": row[1], "description": row[2], "price": row[3]})
        return jsonify({"error": "not found"}), 404
    except Exception as e:
        return jsonify({"error": "db error", "msg": str(e)}), 500

# Create an order (SQLi)
@app.route("/orders", methods=["POST"])
def create_order():
    body = request.get_json(silent=True) or {}
    user_id = body.get("user_id")
    product_id = body.get("product_id")
    quantity = body.get("quantity")

    # Vulnerable to SQL Injection
    sql = f"INSERT INTO orders (user_id, product_id, quantity) VALUES ({user_id}, {product_id}, {quantity})"
    try:
        get_db().execute(sql)
        get_db().commit()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": "db error", "msg": str(e)}), 500

# Get orders for a user (SQLi)
@app.route("/orders/<user_id>", methods=["GET"])
def get_orders(user_id):
    # Vulnerable to SQL Injection
    sql = f"SELECT * FROM orders WHERE user_id = {user_id}"
    try:
        cur = get_db().execute(sql)
        rows = cur.fetchall()
        return jsonify([{"id": r[0], "user_id": r[1], "product_id": r[2], "quantity": r[3], "total_price": r[4], "order_date": r[5]} for r in rows])
    except Exception as e:
        return jsonify({"error": "db error", "msg": str(e)}), 500

# Add a review for a product (SQLi)
@app.route("/reviews", methods=["POST"])
def add_review():
    body = request.get_json(silent=True) or {}
    product_id = body.get("product_id")
    user_id = body.get("user_id")
    review = body.get("review")
    rating = body.get("rating")

    # Vulnerable to SQL Injection
    sql = f"INSERT INTO reviews (product_id, user_id, review, rating) VALUES ({product_id}, {user_id}, '{review}', {rating})"
    try:
        get_db().execute(sql)
        get_db().commit()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": "db error", "msg": str(e)}), 500

# Get reviews for a product (SQLi)
@app.route("/reviews/<product_id>", methods=["GET"])
def get_reviews(product_id):
    # Vulnerable to SQL Injection
    sql = f"SELECT * FROM reviews WHERE product_id = {product_id}"
    try:
        cur = get_db().execute(sql)
        rows = cur.fetchall()
        return jsonify([{"id": r[0], "product_id": r[1], "user_id": r[2], "review": r[3], "rating": r[4], "review_date": r[5]} for r in rows])
    except Exception as e:
        return jsonify({"error": "db error", "msg": str(e)}), 500

if __name__ == "__main__":
    # Create a pages directory for the LFI vulnerability
    if not os.path.exists("/app/pages"):
        os.makedirs("/app/pages")
    with open("/app/pages/index.html", "w") as f:
        f.write("<h1>Welcome to the pages section!</h1>")
    
    # Create a file for path traversal demo
    with open("/app/secret.txt", "w") as f:
        f.write("This is a secret file that should not be accessible!")
        
    app.run(host="0.0.0.0", port=5000)
