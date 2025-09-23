from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib, json, secrets, time

from flask_cors import CORS 

app = Flask(__name__)

CORS(app, resources={r"/api/*": {"origins": "*"}})

# 데모 인메모리 저장 (운영은 DB 사용)
USERS = {}         # username -> {pwd_hash, name, email, createdAt, map_id}
TOKENS = {}        # token -> username
ASCII_MAPS = {}    # map_id -> { "map": { "32":"45", ... }, "version":1 }

PRINTABLE = [i for i in range(32,127)]

def seeded_shuffle(seed:bytes):
    # 간단한 결정론 셔플 (xorshift 유사)
    import struct
    x = struct.unpack("<I", hashlib.sha256(seed).digest()[:4])[0]
    arr = PRINTABLE[:]
    for i in range(len(arr)-1,0,-1):
        x ^= (x<<13)&0xffffffff; x ^= (x>>17); x ^= (x<<5)&0xffffffff
        j = x % (i+1)
        arr[i],arr[j] = arr[j],arr[i]
    return arr

def create_ascii_map_for_user(username:str):
    version = 1
    shuffled = seeded_shuffle(f"user:{username}:v{version}".encode())
    mapping = { str(PRINTABLE[i]) : shuffled[i] for i in range(len(PRINTABLE)) }
    map_id  = hashlib.sha256(f"{username}:{version}".encode()).hexdigest()[:16]
    ASCII_MAPS[map_id] = {"map": mapping, "version": version}

    # 체인에는 원문 대신 해시 기록 (운영: Fabric submitTransaction)
    map_hash = hashlib.sha256(json.dumps(mapping, sort_keys=True).encode()).hexdigest()
    tx_id = "0x"+secrets.token_hex(8)
    print(f"[CHAIN] PutAsciiMap user={username} mapId={map_id} hash={map_hash} v={version} tx={tx_id}")
    return map_id, tx_id

@app.post("/api/signup")
def api_signup():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    name     = (data.get("name") or "").strip()
    email    = (data.get("email") or "").strip()

    # 간단 검증
    if not username or not password or not name or not email:
        return jsonify(error="필수 항목 누락"), 400
    if not (5 <= len(username) <= 10) or not username.isalnum():
        return jsonify(error="아이디 형식이 올바르지 않습니다."), 400
    if not (5 <= len(password) <= 10):
        return jsonify(error="비밀번호 길이(5~10자)를 확인하세요."), 400
    if username in USERS:
        return jsonify(error="이미 존재하는 아이디입니다."), 409

    USERS[username] = {
        "pwd_hash": generate_password_hash(password),
        "name": name, "email": email, "createdAt": time.time()
    }
    map_id, tx_id = create_ascii_map_for_user(username)
    USERS[username]["map_id"] = map_id

    return jsonify(ok=True, asciiMapId=map_id, txId=tx_id), 201

@app.post("/api/login")
def api_login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    u = USERS.get(username)
    if not u or not check_password_hash(u["pwd_hash"], password):
        return jsonify(error="아이디/비밀번호 확인"), 401
    token = secrets.token_urlsafe(32)
    TOKENS[token] = username
    return jsonify(token=token)

@app.get("/api/me/ascii-map")
def api_map():
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): return jsonify(error="인증 필요"), 401
    token = auth.split(" ",1)[1]
    username = TOKENS.get(token)
    if not username: return jsonify(error="인증 만료"), 401
    map_id = USERS[username]["map_id"]
    payload = ASCII_MAPS.get(map_id)
    return jsonify(asciiMap=payload["map"], version=payload["version"])

if __name__ == "__main__":
    # 개발용 실행 (운영은 WSGI/uWSGI+NGINX/IIS ReverseProxy 권장)
    app.run(host="0.0.0.0", port=5000, debug=True)

@app.errorhandler(404)
def not_found(e):
    # API 경로에서만 JSON, 그 외는 기본 404를 쓰고 싶다면 분기 가능
    if request.path.startswith("/api/"):
        return jsonify(error="Not Found"), 404
    return e, 404

@app.errorhandler(500)
def server_error(e):
    # 디버그 HTML 대신 JSON 에러
    return jsonify(error="서버 내부 오류"), 500    