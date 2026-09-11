"""
Authentication engine and SQLite user store for Self-Healing GraphRAG CTI.
Supports Red Team ('HACKER') and SOC Analyst ('USER') roles with JWT session management.
"""

import os
import sqlite3
import hashlib
import hmac
import base64
import json
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

# Environment variables with safe defaults
DB_PATH = os.getenv("AUTH_DB_PATH", os.path.join(os.path.dirname(__file__), "cti_auth.db"))
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-cyber-threat-intel-key-change-in-production")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

# Try importing pyjwt if installed; provide resilient fallback using standard library
try:
    import jwt as pyjwt
    HAS_PYJWT = True
except ImportError:
    HAS_PYJWT = False


def _b64url_encode(data: bytes) -> str:
    """Helper for URL-safe base64 encoding without padding."""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def _b64url_decode(data: str) -> bytes:
    """Helper for URL-safe base64 decoding with restored padding."""
    rem = len(data) % 4
    if rem > 0:
        data += '=' * (4 - rem)
    return base64.urlsafe_b64decode(data.encode('utf-8'))


def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with 100,000 iterations and random salt."""
    if not salt:
        salt = os.urandom(16).hex()
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return f"{salt}${hashed}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against salt$hash string."""
    try:
        salt, _ = hashed_password.split('$', 1)
        expected = hash_password(plain_password, salt)
        return hmac.compare_digest(expected, hashed_password)
    except Exception:
        return False


def get_db_connection() -> sqlite3.Connection:
    """Get SQLite database connection with row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db() -> None:
    """
    Initialize SQLite database schema and seed default credentials:
    - User (SOC Analyst): user / user123 (Role: USER)
    - Hacker (Red Team): hacker / hacker123 (Role: HACKER)
    """
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('USER', 'HACKER', 'ADMIN')),
            display_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Seed default users if they don't exist
    seed_users = [
        ("user", "user123", "USER", "Tier-2 SOC Analyst"),
        ("hacker", "hacker123", "HACKER", "Red Team Adversary Simulator")
    ]

    for username, password, role, display_name in seed_users:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            hashed = hash_password(password)
            cursor.execute(
                "INSERT INTO users (username, hashed_password, role, display_name) VALUES (?, ?, ?, ?)",
                (username, hashed, role, display_name)
            )

    conn.commit()
    conn.close()


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Retrieve user dictionary by username."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, hashed_password, role, display_name FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def authenticate_user(username: str, plain_password: str) -> Optional[Dict[str, Any]]:
    """Verify credentials and return user record if valid."""
    user = get_user_by_username(username)
    if not user:
        return None
    if verify_password(plain_password, user["hashed_password"]):
        # Remove hashed_password from returned payload for security
        return {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "display_name": user["display_name"]
        }
    return None


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": int(expire.timestamp()), "iat": int(time.time())})

    if HAS_PYJWT:
        return pyjwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Standard library fallback for HS256 JWT
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = _b64url_encode(json.dumps(to_encode, separators=(',', ':')).encode('utf-8'))
    signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
    signature = hmac.new(JWT_SECRET.encode('utf-8'), signing_input, hashlib.sha256).digest()
    signature_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify and decode JWT access token."""
    try:
        if HAS_PYJWT:
            payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            return payload

        # Standard library verification fallback
        parts = token.split('.')
        if len(parts) != 3:
            return None
        header_b64, payload_b64, signature_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        expected_sig = hmac.new(JWT_SECRET.encode('utf-8'), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_encode(expected_sig), signature_b64):
            return None

        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode('utf-8'))
        # Check expiration
        if "exp" in payload and payload["exp"] < time.time():
            return None
        return payload
    except Exception:
        return None


# Initialize on load
init_auth_db()
