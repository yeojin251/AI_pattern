# server.py — Capstone Secure Keyboard (Flask API + Analysis/Verify)
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import pandas as pd
import numpy as np
import os, csv, uuid, time, json, hashlib, secrets
import joblib

import analysis  # 분석/프로파일/시각화 함수
from analysis import load_user_data
from feature_spec import build_features, FEATURE_NAMES

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ===== 데모 인메모리 저장 =====
USERS = {}
TOKENS = {}
ASCII_MAPS = {}
PRINTABLE = [i for i in range(32,127)]

def seeded_shuffle(seed: bytes):
    import struct
    x = struct.unpack("<I", hashlib.sha256(seed).digest()[:4])[0]
    arr = PRINTABLE[:]
    for i in range(len(arr)-1,0,-1):
        x ^= (x<<13)&0xffffffff; x ^= (x>>17); x ^= (x<<5)&0xffffffff
        j = x % (i+1)
        arr[i],arr[j] = arr[j],arr[i]
    return arr

def create_ascii_map_for_user(username: str):
    version = 1
    shuffled = seeded_shuffle(f"user:{username}:v{version}".encode())
    mapping = {str(PRINTABLE[i]): shuffled[i] for i in range(len(PRINTABLE))}
    map_id  = hashlib.sha256(f"{username}:{version}".encode()).hexdigest()[:16]
    ASCII_MAPS[map_id] = {"map": mapping, "version": version}
    map_hash = hashlib.sha256(json.dumps(mapping, sort_keys=True).encode()).hexdigest()
    tx_id = "0x"+secrets.token_hex(8)
    print(f"[CHAIN] PutAsciiMap user={username} mapId={map_id} hash={map_hash} v={version} tx={tx_id}")
    return map_id, tx_id

def _auth_user_from_header():
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): return None
    token = auth.split(" ",1)[1]
    return TOKENS.get(token)

# ===== 계정/로그인/매핑 =====
@app.post("/api/signup")
def api_signup():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    name     = (data.get("name") or "").strip()
    email    = (data.get("email") or "").strip()

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
    if not user: return jsonify(error="인증 필요"), 401
    map_id = USERS[user]["map_id"]
    payload = ASCII_MAPS.get(map_id)
    return jsonify(asciiMap=payload["map"], version=payload["version"])

# ===== 패턴 학습(수집) =====
DATA_DIR = os.path.join(os.path.dirname(__file__), "data_biometrics")
os.makedirs(DATA_DIR, exist_ok=True)
SESS = {}

def _active_session_for(user):
    for sid, s in SESS.items():
        if s["user"] == user and s["active"]:
            return sid, s
    return None, None

@app.post("/api/pattern/start")
def pattern_start():
    user = _auth_user_from_header()
    if not user: return jsonify(error="인증 필요"), 401
    j = request.get_json(silent=True) or {}
    policy = j.get("policy", "threshold")
    min_events = int(j.get("min_events", 600))

    sid_active, s_active = _active_session_for(user)
    if sid_active:
        return jsonify(ok=True, session_id=sid_active, already_active=True,
                       total=s_active["count"], file=os.path.basename(s_active["path"]))

    session_id = uuid.uuid4().hex[:12]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    fpath = os.path.join(DATA_DIR, f"{user}-{session_id}-{stamp}.csv")
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
    user = _auth_user_from_header()
    if not user: return jsonify(error="인증 필요"), 401

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
                tsu = float(r.get("ts_up", tsd))
                dwell = float(r.get("dwell", r.get("dwell_ms", 0)))
                flight = r.get("flight", r.get("flight_ms", None))
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
    user = _auth_user_from_header()
    if not user: return jsonify(error="인증 필요"), 401
    j = request.get_json(force=True)
    sid = j.get("session_id")
    if not sid or sid not in SESS:
        return jsonify(ok=False, msg="invalid session"), 400
    s = SESS[sid]
    if s["user"] != user:
        return jsonify(ok=False, msg="owner mismatch"), 403
    s["active"] = False
    return jsonify(ok=True, total=s["count"], file=os.path.basename(s["path"]))

@app.get("/api/pattern/status")
def pattern_status():
    user = _auth_user_from_header()
    if not user: return jsonify(error="인증 필요"), 401
    sid = request.args.get("sid")
    mine = {k:v for k,v in SESS.items() if v["user"] == user}
    if sid:
        if sid not in mine:
            return jsonify(error="invalid or not my session"), 400
        s = mine[sid]
        size = os.path.getsize(s["path"]) if os.path.exists(s["path"]) else 0
        return jsonify(session_id=sid, active=s["active"], total=s["count"],
                       file=os.path.basename(s["path"]), bytes=size)
    out=[]
    for k,s in mine.items():
        size = os.path.getsize(s["path"]) if os.path.exists(s["path"]) else 0
        out.append({"session_id":k, "active":s["active"], "total":s["count"],
                    "file":os.path.basename(s["path"]), "bytes":size})
    return jsonify(out)

# ===== 분석/프로파일/시각화 =====
@app.post("/api/pattern/analyze")
def analyze_pattern():
    user = _auth_user_from_header()
    if not user: return jsonify(error="인증이 필요합니다."), 401
    try:
        print(f"[{user}] 분석 시작")
        feature_vector = analysis.create_feature_vector(user)
        if not feature_vector:
            return jsonify(error="분석할 데이터가 부족하거나 없음"), 404

        analysis.create_and_save_user_profile(user)
        analysis.visualize_user_data(user)

        summary = {
            "user": user,
            "message": "분석 및 프로파일링이 성공적으로 완료되었습니다.",
            "dwell_mean": feature_vector.get("dwell_mean"),
            "flight_mean": feature_vector.get("flight_mean"),
            "typing_speed_cps": feature_vector.get("typing_kps"),
            "backspace_ratio": feature_vector.get("backspace_ratio"),
        }
        return jsonify(summary), 200
    except Exception as e:
        app.logger.error(f"[{user}] 분석 오류: {e}", exc_info=True)
        return jsonify(error=f"서버 분석 오류: {e}"), 500

# ===== 실시간 인증 =====
@app.post("/api/pattern/verify")
def verify_pattern():
    user = _auth_user_from_header()
    if not user: return jsonify(error="인증이 필요합니다."), 401

    data = request.get_json(force=True)
    samples = data.get("samples", [])
    if not samples:
        return jsonify(error="분석할 샘플 데이터가 없습니다."), 400

    model_path   = f"user_models/{user}_iforest_model.pkl"
    profile_path = f"user_profiles/{user}_profile.pkl"
    if not (os.path.exists(model_path) and os.path.exists(profile_path)):
        return jsonify(error=f"'{user}'의 모델/프로필이 없습니다. 먼저 분석 및 학습을 완료하세요."), 404

    try:
        model   = joblib.load(model_path)
        profile = joblib.load(profile_path)
        scaler  = profile["scaler"]

        live_df = pd.DataFrame(samples)
        X_live  = build_features(live_df).dropna()
        if X_live.empty:
            return jsonify(error="유효한 피처가 없습니다."), 400

        Xz = scaler.transform(X_live.values)
        preds = model.predict(Xz)  # 1: 정상, -1: 이상
        inlier_ratio = float((preds == 1).sum() / len(preds))
        is_user = bool(inlier_ratio >= 0.5)  # 필요시 0.6~0.7

        return jsonify({"is_user": is_user, "score": f"{inlier_ratio:.2%}"})
    except Exception as e:
        app.logger.error(f"[{user}] verify 오류: {e}", exc_info=True)
        return jsonify(error=f"인증 중 서버 오류: {e}"), 500

# ===== 에러 핸들러/실행 =====
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify(error="Not Found"), 404
    return e, 404

@app.errorhandler(500)
def server_error(e):
    return jsonify(error="서버 내부 오류"), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
