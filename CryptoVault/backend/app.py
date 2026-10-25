import base64
import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.exceptions import InvalidSignature
from io import BytesIO

app = Flask(__name__)
CORS(app)
DB = os.path.join(os.path.dirname(__file__), "cryptovault.db")
TOKENS = {}

def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL,
            created_at TEXT NOT NULL
        )""")

def user_for_token():
    token = request.headers.get("Authorization", "").replace("Bearer ", "", 1)
    username = TOKENS.get(token)
    if not username:
        return None
    with db() as con:
        return con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = user_for_token()
        if not user:
            return jsonify({"error": "Please log in first."}), 401
        request.current_user = user
        return fn(*args, **kwargs)
    return wrapper

def pem_public(user):
    return user["public_key"]

def pem_private(user):
    return serialization.load_pem_private_key(user["private_key"].encode(), password=None)

@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "CryptoVault API"})

@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    if len(username) < 3 or len(password) < 6:
        return jsonify({"error": "Username must be at least 3 characters and password at least 6 characters."}), 400
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    pub_pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    try:
        with db() as con:
            con.execute("INSERT INTO users(username,password_hash,public_key,private_key,created_at) VALUES(?,?,?,?,?)",
                        (username, generate_password_hash(password), pub_pem, priv_pem, datetime.now(timezone.utc).isoformat()))
    except sqlite3.IntegrityError:
        return jsonify({"error": "That username is already registered."}), 409
    return jsonify({"message": "Account created. Log in to use CryptoVault."}), 201

@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    with db() as con:
        user = con.execute("SELECT * FROM users WHERE username=?", (str(data.get("username","")).strip(),)).fetchone()
    if not user or not check_password_hash(user["password_hash"], str(data.get("password",""))):
        return jsonify({"error": "Invalid username or password."}), 401
    token = secrets.token_urlsafe(32)
    TOKENS[token] = user["username"]
    return jsonify({"token": token, "username": user["username"], "public_key": user["public_key"],
                    "private_key": user["private_key"], "message": "Logged in successfully."})

@app.post("/api/logout")
def logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "", 1)
    TOKENS.pop(token, None)
    return jsonify({"message": "Logged out."})

@app.get("/api/me")
@login_required
def me():
    u = request.current_user
    return jsonify({"username": u["username"], "public_key": u["public_key"]})

@app.get("/api/certificate")
@login_required
def certificate():
    u = request.current_user
    private = pem_private(u)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u["username"])])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(private.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(private, hashes.SHA256()))
    payload = cert.public_bytes(serialization.Encoding.PEM)
    return send_file(BytesIO(payload), mimetype="application/x-pem-file",
                     as_attachment=True, download_name=f"{u['username']}-certificate.pem")

@app.post("/api/rsa/encrypt")
@login_required
def rsa_encrypt():
    data = request.get_json(silent=True) or {}
    try:
        public = serialization.load_pem_public_key(str(data.get("public_key") or request.current_user["public_key"]).encode())
        ciphertext = public.encrypt(str(data.get("message","")).encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return jsonify({"ciphertext": base64.b64encode(ciphertext).decode()})
    except Exception as e:
        return jsonify({"error": "Encryption failed. Check the public key and message length."}), 400

@app.post("/api/rsa/decrypt")
@login_required
def rsa_decrypt():
    data = request.get_json(silent=True) or {}
    try:
        ciphertext = base64.b64decode(data.get("ciphertext",""), validate=True)
        plain = pem_private(request.current_user).decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        return jsonify({"plaintext": plain.decode()})
    except Exception:
        return jsonify({"error": "Decryption failed. Ensure the ciphertext was encrypted for your account's key."}), 400

@app.post("/api/rsa/sign")
@login_required
def rsa_sign():
    data = request.get_json(silent=True) or {}
    signature = pem_private(request.current_user).sign(str(data.get("message","")).encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return jsonify({"signature": base64.b64encode(signature).decode(), "algorithm": "RSA-PSS / SHA-256"})

@app.post("/api/rsa/verify")
@login_required
def rsa_verify():
    data = request.get_json(silent=True) or {}
    try:
        public = serialization.load_pem_public_key(str(data.get("public_key") or request.current_user["public_key"]).encode())
        public.verify(base64.b64decode(data.get("signature",""), validate=True), str(data.get("message","")).encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return jsonify({"valid": True, "message": "Signature is valid."})
    except (InvalidSignature, ValueError, Exception):
        return jsonify({"valid": False, "message": "Signature is invalid or the input is malformed."})

@app.post("/api/dh")
@login_required
def dh():
    data = request.get_json(silent=True) or {}
    try:
        p, g = int(data.get("p", 23)), int(data.get("g", 5))
        a, b = int(data.get("a", 6)), int(data.get("b", 15))
        if p < 5 or p > 1000000007 or not (1 < g < p) or a < 1 or b < 1:
            raise ValueError()
        A, B = pow(g, a, p), pow(g, b, p)
        s1, s2 = pow(B, a, p), pow(A, b, p)
        return jsonify({"p":p,"g":g,"a":a,"b":b,"A":A,"B":B,"alice_secret":s1,"bob_secret":s2,"match":s1==s2})
    except Exception:
        return jsonify({"error": "Use integer values with p >= 5, 1 < g < p, and positive private keys."}), 400

# Educational ElGamal signature using SHA-512 digest reduced modulo p-1.
@app.post("/api/elgamal/sign")
@login_required
def elgamal_sign():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message",""))
    p = int(data.get("p", 467)); g = int(data.get("g", 2)); x = int(data.get("x", 127))
    try:
        if p < 5 or not (1 < g < p) or not (1 <= x <= p-2):
            raise ValueError()
        y = pow(g, x, p)
        digest_hex = hashlib.sha512(message.encode()).hexdigest()
        m = int(digest_hex, 16) % (p - 1)
        while True:
            k = secrets.randbelow(p - 2) + 1
            if __import__("math").gcd(k, p - 1) == 1:
                break
        r = pow(g, k, p)
        s = ((m - x*r) * pow(k, -1, p-1)) % (p-1)
        return jsonify({"hash":digest_hex,"p":p,"g":g,"public_y":y,"signature":{"r":r,"s":s},"private_x":x})
    except Exception:
        return jsonify({"error": "Invalid ElGamal parameters. Use p >= 5, 1 < g < p, and 1 <= x <= p-2."}), 400

@app.post("/api/elgamal/verify")
@login_required
def elgamal_verify():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message",""))
    try:
        p, g, y = int(data["p"]), int(data["g"]), int(data["y"])
        r, s = int(data["r"]), int(data["s"])
        digest_hex = hashlib.sha512(message.encode()).hexdigest()
        m = int(digest_hex,16) % (p-1)
        valid = 0 < r < p and 0 <= s < p-1 and pow(g,m,p) == (pow(y,r,p)*pow(r,s,p)) % p
        return jsonify({"valid":valid,"hash":digest_hex,"message":"Signature is valid." if valid else "Signature is invalid."})
    except Exception:
        return jsonify({"valid":False,"message":"Check p, g, y, r and s values."}), 400

if __name__ == "__main__":
    init_db()
app.run(host="127.0.0.1", port=5001, debug=True)
