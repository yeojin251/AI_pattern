# server.py — Capstone Secure Keyboard (Flask API)
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

import hashlib, json, secrets, time
import os, csv, uuid  # 패턴 학습 로그 저장용

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ============================ 데모 인메모리 저장 (운영은 DB) ============================
USERS = {}         # username -> {pwd_hash, name, email, createdAt, map_id}
TOKENS = {}        # token -> username
ASCII_MAPS = {}    # map_id -> { "map": { "32":"45", ... }, "version":1 }

PRINTABLE = [i for i in range(32,127)]

def seeded_shuffle(seed: bytes):
    """사용자/버전 고정 시드 기반 결정론 셔플"""
    import struct
    x = struct.unpack("<I", hashlib.sha256(seed).digest()[:4])[0]
    arr = PRINTABLE[:]
    for i in range(len(arr)-1, 0, -1):
        x ^= (x << 13) & 0xffffffff
        x ^= (x >> 17)
        x ^= (x << 5) & 0xffffffff
        j = x % (i + 1)
        arr[i], arr[j] = arr[j], arr[i]
    return arr

def create_ascii_map_for_user(username: str):
    version = 1
    shuffled = seeded_shuffle(f"user:{username}:v{version}".encode())
    mapping = {str(PRINTABLE[i]): shuffled[i] for i in range(len(PRINTABLE))}
    map_id  = hashlib.sha256(f"{username}:{version}".encode()).hexdigest()[:16]
    ASCII_MAPS[map_id] = {"map": mapping, "version": version}

    # 체인에는 원문 대신 해시 기록 (운영: Fabric submitTransaction)
    map_hash = hashlib.sha256(json.dumps(mapping, sort_keys=True).encode()).hexdigest()
    tx_id = "0x" + secrets.token_hex(8)
    print(f"[CHAIN] PutAsciiMap user={username} mapId={map_id} hash={map_hash} v={version} tx={tx_id}")
    return map_id, tx_id

# ============================ 인증 헬퍼 ============================
def _auth_user_from_header():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1]
    return TOKENS.get(token)

# ============================ 계정 / 로그인 / 매핑 ============================
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
    user = _auth_user_from_header()
    if not user:
        return jsonify(error="인증 필요"), 401
    map_id = USERS[user]["map_id"]
    payload = ASCII_MAPS.get(map_id)
    return jsonify(asciiMap=payload["map"], version=payload["version"])

# ============================ 패턴 학습(키 이벤트 수집) ============================
# 저장 디렉터리
DATA_DIR = os.path.join(os.path.dirname(__file__), "data_biometrics")
os.makedirs(DATA_DIR, exist_ok=True)

# 세션 상태: session_id -> {...}
SESS = {}  # {"user":.., "path":.., "count":0, "policy":"threshold"|"manual", "min_events":600, "active":True}

def _active_session_for(user):
    for sid, s in SESS.items():
        if s["user"] == user and s["active"]:
            return sid, s
    return None, None

@app.post("/api/pattern/start")
def pattern_start():
    """수집 세션 생성. policy: threshold|manual, min_events: 임계 이벤트 수
       이미 활성 세션이 있으면 그 세션을 재사용(중복 파일 방지)"""
    user = _auth_user_from_header()
    if not user:
        return jsonify(error="인증 필요"), 401
    j = (request.get_json(silent=True) or {})
    policy = j.get("policy", "threshold")
    min_events = int(j.get("min_events", 600))

    # 기존 활성 세션 재사용
    sid_active, s_active = _active_session_for(user)
    if sid_active:
        return jsonify(ok=True, session_id=sid_active,
                       already_active=True,
                       total=s_active["count"],
                       file=os.path.basename(s_active["path"]))

    # 새 세션 생성
    session_id = uuid.uuid4().hex[:12]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    fpath = os.path.join(DATA_DIR, f"{user}-{session_id}-{stamp}.csv")
    # CSV 헤더 작성 (prev_code 포함)
    with open(fpath, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ts_down","ts_up","dwell_ms","flight_ms","code","prev_code","key"])

    SESS[session_id] = {
        "user": user, "path": fpath, "count": 0,
        "policy": policy, "min_events": min_events, "active": True
    }
    return jsonify(ok=True, session_id=session_id)

@app.post("/api/pattern/collect")
def pattern_collect():
    """키다운/업 기반 특징 배치 수집"""
    user = _auth_user_from_header()
    if not user:
        return jsonify(error="인증 필요"), 401

    j = request.get_json(force=True)
    sid = j.get("session_id")
    samples = j.get("samples", [])
    if not sid or sid not in SESS:
        return jsonify(ok=False, msg="invalid session"), 400
    s = SESS[sid]
    if not s["active"]:
        return jsonify(ok=False, msg="inactive session"), 400
    if s["user"] != user:
        return jsonify(ok=False, msg="owner mismatch"), 403

    added = 0
    with open(s["path"], "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        for r in samples:
            try:
                tsd = float(r.get("ts_down", 0))
                tsu = float(r.get("ts_up", 0))
                dwell = float(r.get("dwell", 0))
                flight = r.get("flight", None)
                flight = "" if flight is None else float(flight)
                code = str(r.get("code", ""))
                prev_code = str(r.get("prev_code", ""))
                key  = str(r.get("key", ""))
                if dwell >= 0:
                    w.writerow([tsd, tsu, dwell, flight, code, prev_code, key])
                    added += 1
            except Exception:
                pass
    s["count"] += added

    stop_now = False
    if s["policy"] == "threshold" and s["count"] >= s["min_events"]:
        s["active"] = False
        stop_now = True

    return jsonify(ok=True, added=added, total=s["count"], stop=stop_now)

@app.post("/api/pattern/stop")
def pattern_stop():
    """수집 세션 수동 정지"""
    user = _auth_user_from_header()
    if not user:
        return jsonify(error="인증 필요"), 401

    j = request.get_json(force=True)
    sid = j.get("session_id")
    if not sid or sid not in SESS:
        return jsonify(ok=False, msg="invalid session"), 400
    s = SESS[sid]
    if s["user"] != user:
        return jsonify(ok=False, msg="owner mismatch"), 403
    s["active"] = False
    return jsonify(ok=True, total=s["count"], file=os.path.basename(s["path"]))

# 진행상태 확인(선택)
@app.get("/api/pattern/status")
def pattern_status():
    user = _auth_user_from_header()
    if not user:
        return jsonify(error="인증 필요"), 401
    sid = request.args.get("sid")
    mine = {k:v for k,v in SESS.items() if v["user"] == user}
    if sid:
        if sid not in mine:
            return jsonify(error="invalid or not my session"), 400
        s = mine[sid]
        size = os.path.getsize(s["path"]) if os.path.exists(s["path"]) else 0
        return jsonify(session_id=sid, active=s["active"], total=s["count"], file=os.path.basename(s["path"]), bytes=size)
    out=[]
    for k,s in mine.items():
        size = os.path.getsize(s["path"]) if os.path.exists(s["path"]) else 0
        out.append({"session_id":k, "active":s["active"], "total":s["count"], "file":os.path.basename(s["path"]), "bytes":size})
    return jsonify(out)

# ============================ 에러 핸들러 ============================
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify(error="Not Found"), 404
    return e, 404

@app.errorhandler(500)
def server_error(e):
    return jsonify(error="서버 내부 오류"), 500

# ============================ 개발용 실행 ============================
if __name__ == "__main__":
    # 운영은 WSGI/uWSGI + Reverse Proxy 권장
    app.run(host="0.0.0.0", port=5000, debug=True)
