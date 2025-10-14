# server.py — Capstone Secure Keyboard (Flask API + Analysis Endpoint + Absolute Paths)
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import pandas as pd

import hashlib, json, secrets, time
import os, csv, uuid  # 패턴 학습 로그 저장용

# ============================ 분석 기능 추가 ============================
# analysis.py 파일의 함수 사용
import analysis

# ============================ 경로(절대경로) 설정 ============================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data_biometrics")
MODEL_DIR = os.path.join(BASE_DIR, "user_models")
PROFILE_DIR = os.path.join(BASE_DIR, "user_profiles")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(PROFILE_DIR, exist_ok=True)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ============================ 데모 인메모리 저장 (운영은 DB) ============================
USERS = {}  # username -> {pwd_hash, name, email, createdAt, map_id}
TOKENS = {}  # token -> username
ASCII_MAPS = {}  # map_id -> { "map": { "32":"45", ... }, "version":1 }

PRINTABLE = [i for i in range(32, 127)]


def seeded_shuffle(seed: bytes):
    """사용자/버전 고정 시드 기반 결정론 셔플"""
    import struct
    x = struct.unpack("<I", hashlib.sha256(seed).digest()[:4])[0]
    arr = PRINTABLE[:]
    for i in range(len(arr) - 1, 0, -1):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        j = x % (i + 1)
        arr[i], arr[j] = arr[j], arr[i]
    return arr


def create_ascii_map_for_user(username: str):
    version = 1
    shuffled = seeded_shuffle(f"user:{username}:v{version}".encode())
    mapping = {str(PRINTABLE[i]): shuffled[i] for i in range(len(PRINTABLE))}
    map_id = hashlib.sha256(f"{username}:{version}".encode()).hexdigest()[:16]
    ASCII_MAPS[map_id] = {"map": mapping, "version": version}

    # 체인에는 원문 대신 해시 기록 (운영: Fabric submitTransaction)
    map_hash = hashlib.sha256(json.dumps(mapping, sort_keys=True).encode()).hexdigest()
    tx_id = "0x" + secrets.token_hex(8)
    print(
        f"[CHAIN] PutAsciiMap user={username} mapId={map_id} hash={map_hash} v={version} tx={tx_id}"
    )
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
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()

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
        "name": name,
        "email": email,
        "createdAt": time.time(),
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
# 세션 상태: session_id -> {...}
SESS = (
    {}
)  # {"user":.., "path":.., "count":0, "policy":"threshold"|"manual", "min_events":600, "active":True}


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
    j = request.get_json(silent=True) or {}
    policy = j.get("policy", "threshold")
    min_events = int(j.get("min_events", 600))

    # 기존 활성 세션 재사용
    sid_active, s_active = _active_session_for(user)
    if sid_active:
        return jsonify(
            ok=True,
            session_id=sid_active,
            already_active=True,
            total=s_active["count"],
            file=os.path.basename(s_active["path"]),
        )

    # 새 세션 생성
    session_id = uuid.uuid4().hex[:12]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    fpath = os.path.join(DATA_DIR, f"{user}-{session_id}-{stamp}.csv")
    # CSV 헤더 작성 (prev_code 포함)
    with open(fpath, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(
            ["ts_down", "ts_up", "dwell_ms", "flight_ms", "code", "prev_code", "key"]
        )

    SESS[session_id] = {
        "user": user,
        "path": fpath,
        "count": 0,
        "policy": policy,
        "min_events": min_events,
        "active": True,
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
                key = str(r.get("key", ""))
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


@app.get("/api/pattern/status")
def pattern_status():
    user = _auth_user_from_header()
    if not user:
        return jsonify(error="인증 필요"), 401
    sid = request.args.get("sid")
    mine = {k: v for k, v in SESS.items() if v["user"] == user}
    if sid:
        if sid not in mine:
            return jsonify(error="invalid or not my session"), 400
        s = mine[sid]
        size = os.path.getsize(s["path"]) if os.path.exists(s["path"]) else 0
        return jsonify(
            session_id=sid,
            active=s["active"],
            total=s["count"],
            file=os.path.basename(s["path"]),
            bytes=size,
        )
    out = []
    for k, s in mine.items():
        size = os.path.getsize(s["path"]) if os.path.exists(s["path"]) else 0
        out.append(
            {
                "session_id": k,
                "active": s["active"],
                "total": s["count"],
                "file": os.path.basename(s["path"]),
                "bytes": size,
            }
        )
    return jsonify(out)


# ============================ 패턴 분석 API ============================
@app.route("/api/pattern/analyze", methods=["POST"])
def analyze_pattern():
    """
    사용자의 수집된 모든 타이핑 데이터를 분석하여 특징 벡터를 추출하고,
    사용자 프로필(표준화 모델)을 생성/저장하며, 데이터 분포를 시각화합니다.
    """
    user = _auth_user_from_header()
    if not user:
        return jsonify(error="인증이 필요합니다."), 401

    try:
        print(f"[{user}] 사용자의 데이터 분석을 시작합니다.")
        feature_vector = analysis.create_feature_vector(user)
        if not feature_vector:
            print(f"[{user}] 분석할 데이터가 부족합니다.")
            return jsonify(error="분석할 데이터가 부족하거나 찾을 수 없습니다."), 404

        print(f"[{user}] 사용자 프로필 생성/저장.")
        analysis.create_and_save_user_profile(user)

        print(f"[{user}] 데이터 분포 시각화 생성.")
        analysis.visualize_user_data(user)

        summary = {
            "user": user,
            "message": "분석 및 프로파일링이 성공적으로 완료되었습니다.",
            "dwell_mean": feature_vector.get("dwell_mean"),
            "flight_mean": feature_vector.get("flight_mean"),
            "typing_speed_cps": feature_vector.get("typing_kps"),
            "backspace_ratio": feature_vector.get("backspace_ratio"),
        }
        print(f"[{user}] 분석 완료.")
        return jsonify(summary), 200

    except Exception as e:
        app.logger.error(
            f"사용자 '{user}'의 데이터 분석 중 오류 발생: {e}", exc_info=True
        )
        return jsonify(error=f"서버에서 분석 중 오류가 발생했습니다: {str(e)}"), 500


# ============================ 실시간 인증 API ============================
import numpy as np
import joblib

@app.route("/api/pattern/verify", methods=["POST"])
def verify_pattern():
    """실시간 타이핑 데이터 샘플을 받아 사용자 본인 여부를 판별합니다."""
    user = _auth_user_from_header()
    if not user:
        return jsonify(error="인증이 필요합니다."), 401

    data = request.get_json(force=True)
    samples = data.get("samples", [])  # [{'dwell_ms': 102, 'flight_ms': 88}, ...]

    if not samples:
        return jsonify(error="분석할 샘플 데이터가 없습니다."), 400

    # 절대경로 확인/로그
    model_path = os.path.join(MODEL_DIR,  f"{user}_iforest_model.pkl")
    profile_path = os.path.join(PROFILE_DIR, f"{user}_profile.pkl")
    print(f"[VERIFY] user={user} files model={'OK' if os.path.exists(model_path) else 'MISS'} "
          f"profile={'OK' if os.path.exists(profile_path) else 'MISS'}")

    try:
        model = joblib.load(model_path)
        profile = joblib.load(profile_path)
        scaler = profile["scaler"]

        live_df = pd.DataFrame(samples)
        features = ["dwell_ms", "flight_ms"]  # 학습과 동일
        live_data = live_df[features].dropna()

        if live_data.empty:
            return jsonify(error="유효한 데이터가 없습니다."), 400

        live_data_scaled = scaler.transform(live_data)
        predictions = model.predict(live_data_scaled)  # 1=inlier, -1=outlier
        inlier_ratio = float(np.sum(predictions == 1)) / len(predictions)

        # 임계값(필요시 0.6~0.7로 조정 가능)
        is_user = bool(inlier_ratio >= 0.5)

        return jsonify(
            {
                "is_user": is_user,
                "score": f"{inlier_ratio:.2%}",
                "message": "인증 성공" if is_user else "인증 실패: 타이핑 패턴이 일치하지 않습니다.",
            }
        )

    except FileNotFoundError:
        return (
            jsonify(error=f"'{user}'의 학습된 모델 또는 프로필을 찾을 수 없습니다."),
            404,
        )
    except Exception as e:
        app.logger.error(f"[{user}] 인증 중 오류: {e}", exc_info=True)
        return jsonify(error=f"인증 중 서버 오류 발생: {e}"), 500


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
    # 운영 환경에서는 WSGI(uWSGI/Gunicorn) + Reverse Proxy 권장
    app.run(host="0.0.0.0", port=5000, debug=True)
