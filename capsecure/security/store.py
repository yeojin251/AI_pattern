# security/store.py
import os, json, base64, hashlib, secrets
from typing import Optional

def _data_dir(base_dir: str) -> str:
    d = os.path.join(base_dir, "data")
    os.makedirs(d, exist_ok=True)
    return d

def _users_path(base_dir: str) -> str:
    return os.path.join(_data_dir(base_dir), "users.json")

def _load_all(base_dir: str) -> list:
    p = _users_path(base_dir)
    if not os.path.exists(p):
        return []
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def _save_all(base_dir: str, users: list):
    p = _users_path(base_dir)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

def _hash_pw(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000, dklen=32)

def register_user(username: str, password: str, base_dir: str):
    username = (username or "").strip()
    if not username:
        raise ValueError("아이디를 입력하세요.")
    if not password or len(password) < 6:
        raise ValueError("비밀번호는 최소 6자 이상이어야 합니다.")

    users = _load_all(base_dir)
    if any(u["username"].lower() == username.lower() for u in users):
        raise ValueError("이미 존재하는 아이디입니다.")

    salt = secrets.token_bytes(16)
    pw_hash = _hash_pw(password, salt)

    users.append({
        "username": username,
        "salt": base64.b64encode(salt).decode(),
        "pw": base64.b64encode(pw_hash).decode()
    })
    _save_all(base_dir, users)

def login_user(username: str, password: str, base_dir: str) -> bool:
    users = _load_all(base_dir)
    user = next((u for u in users if u["username"].lower() == (username or "").lower()), None)
    if not user:
        return False
    salt = base64.b64decode(user["salt"])
    expect = base64.b64decode(user["pw"])
    calc = _hash_pw(password or "", salt)
    return secrets.compare_digest(expect, calc)
