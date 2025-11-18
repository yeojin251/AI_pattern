# server.py — Capstone Secure Keyboard (Flask API + SQLite/SQLAlchemy + Analysis/Verify)
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import UniqueConstraint
import os, csv, uuid, time, json, hashlib, secrets
import pandas as pd
import joblib
import numpy as np  # 추가

# 분석/프로파일/시각화
import analysis
from feature_spec import build_features, FEATURE_NAMES

# =========================================
# 기본 경로/디렉터리
# =========================================
BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(BASE_DIR, "app.db")

os.makedirs(os.path.join(BASE_DIR, "data_biometrics"), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "user_profiles"), exist_ok=True)
os.makedirs(os.path.join(BASE_DIR, "user_models"), exist_ok=True)

# =========================================
# Flask / DB 설정
# =========================================
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JSON_AS_ASCII"] = False
CORS(app, resources={r"/api/*": {"origins": "*"}})
db = SQLAlchemy(app)


# =========================================
# DB 모델
# =========================================
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, index=True, nullable=False)
    pwd_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.Float, default=lambda: time.time())
    map_id = db.Column(db.String(32), nullable=True)  # ascii map id


class AsciiMap(db.Model):
    __tablename__ = "ascii_maps"
    id = db.Column(db.Integer, primary_key=True)
    map_id = db.Column(db.String(32), unique=True, index=True, nullable=False)
    version = db.Column(db.Integer, default=1)
    mapping = db.Column(db.Text, nullable=False)  # JSON 문자열
    created_at = db.Column(db.Float, default=lambda: time.time())


class SessionToken(db.Model):
    __tablename__ = "session_tokens"
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, index=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.Float, default=lambda: time.time())
    user = db.relationship("User", backref="tokens")


# 유니크 제약 (참고용)
UniqueConstraint(User.username, name="uq_users_username")

# =========================================
# 유틸: ASCII map 생성
# =========================================
PRINTABLE = [i for i in range(32, 127)]


def seeded_shuffle(seed: bytes):
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

    mapping_json = json.dumps(mapping, sort_keys=True, ensure_ascii=False)
    rec = AsciiMap(map_id=map_id, version=version, mapping=mapping_json)
    db.session.add(rec)
    db.session.commit()

    map_hash = hashlib.sha256(mapping_json.encode()).hexdigest()
    tx_id = "0x" + secrets.token_hex(8)
    print(
        f"[CHAIN] PutAsciiMap user={username} mapId={map_id} hash={map_hash} v={version} tx={tx_id}"
    )
    return map_id, tx_id


def _auth_user_from_header():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1]
    tok = SessionToken.query.filter_by(token=token).first()
    if not tok:
        return None
    return tok.user.username  # 서버 나머지 부분은 username만 알면 되니까 이렇게 줌


# =========================================
# 회원 / 로그인 / 매핑
# =========================================
@app.post("/api/signup")
def api_signup():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()

    if not username or not password or not name or not email:
        return jsonify(error="필수 항목 누락"), 400
    if not (5 <= len(username) <= 10) or not username.isalnum():
        return jsonify(error="아이디 형식이 올바르지 않습니다."), 400
    if not (5 <= len(password) <= 10):
        return jsonify(error="비밀번호 길이(5~10자)를 확인하세요."), 400

    if User.query.filter_by(username=username).first():
        return jsonify(error="이미 존재하는 아이디입니다."), 409

    u = User(
        username=username,
        pwd_hash=generate_password_hash(password),
        name=name,
        email=email,
    )
    db.session.add(u)
    db.session.commit()

    map_id, tx_id = create_ascii_map_for_user(username)
    u.map_id = map_id
    db.session.commit()

    return jsonify(ok=True, asciiMapId=map_id, txId=tx_id), 201


@app.post("/api/login")
def api_login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    u = User.query.filter_by(username=username).first()
    if not u or not check_password_hash(u.pwd_hash, password):
        return jsonify(error="아이디/비밀번호 확인"), 401

    token_str = secrets.token_urlsafe(32)
    tok = SessionToken(token=token_str, user_id=u.id)
    db.session.add(tok)
    db.session.commit()

    return jsonify(token=token_str)


@app.get("/api/me/ascii-map")
def api_map():
    user = _auth_user_from_header()
    if not user:
        return jsonify(error="인증 필요"), 401

    u = User.query.filter_by(username=user).first()
    if not u or not u.map_id:
        return jsonify(error="매핑 없음"), 404

    amap = AsciiMap.query.filter_by(map_id=u.map_id).first()
    if not amap:
        return jsonify(error="매핑 없음"), 404

    mapping = json.loads(amap.mapping)
    return jsonify(asciiMap=mapping, version=amap.version)


# =========================================
# 패턴 수집 (이 부분은 파일 방식 유지)
# =========================================
DATA_DIR = os.path.join(BASE_DIR, "data_biometrics")
SESS = {}  # session_id -> {user, path, count, ...}


def _active_session_for(user):
    for sid, s in SESS.items():
        if s["user"] == user and s["active"]:
            return sid, s
    return None, None


@app.post("/api/pattern/start")
def pattern_start():
    user = _auth_user_from_header()
    if not user:
        return jsonify(error="인증 필요"), 401

    j = request.get_json(silent=True) or {}
    policy = j.get("policy", "threshold")
    min_events = int(j.get("min_events", 600))

    sid_active, s_active = _active_session_for(user)
    if sid_active:
        return jsonify(
            ok=True,
            session_id=sid_active,
            already_active=True,
            total=s_active["count"],
            file=os.path.basename(s_active["path"]),
        )

    session_id = uuid.uuid4().hex[:12]
    stamp = time.strftime("%Y%m%d-%H%M%S")
    fpath = os.path.join(DATA_DIR, f"{user}-{session_id}-{stamp}.csv")
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
                tsu = float(r.get("ts_up", tsd))
                dwell = float(r.get("dwell", r.get("dwell_ms", 0)))
                flight = r.get("flight", r.get("flight_ms", None))
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


# =========================================
# 분석/프로파일/시각화
# =========================================
@app.post("/api/pattern/analyze")
def analyze_pattern():
    user = _auth_user_from_header()
    if not user:
        return jsonify(error="인증이 필요합니다."), 401
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


# =========================================
# 실시간 인증
# =========================================
@app.post("/api/pattern/verify")
def verify_pattern():
    user = _auth_user_from_header()
    if not user:
        return jsonify(error="인증이 필요합니다."), 401

    data = request.get_json(force=True)
    samples = data.get("samples", [])
    if not samples:
        return jsonify(error="분석할 샘플 데이터가 없습니다."), 400

    model_path = os.path.join(BASE_DIR, f"user_models/{user}_iforest_model.pkl")
    profile_path = os.path.join(BASE_DIR, f"user_profiles/{user}_profile.pkl")
    if not (os.path.exists(model_path) and os.path.exists(profile_path)):
        return (
            jsonify(
                error=f"'{user}'의 모델/프로필이 없습니다. 먼저 분석 및 학습을 완료하세요."
            ),
            404,
        )

    try:
        model = joblib.load(model_path)
        profile = joblib.load(profile_path)
        scaler = profile["scaler"]
        pair_stats = profile.get("pair_stats", {})

        live_df = pd.DataFrame(samples)
        X_live = build_features(live_df).dropna()
        if X_live.empty:
            return jsonify(error="유효한 피처가 없습니다."), 400

        Xz = scaler.transform(X_live.values)
        preds = model.predict(Xz)
        inlier_ratio = float((preds == 1).sum() / len(preds))

        # 보조 점수 (digram 기반)
        z_list = []
        if {"prev_code", "code", "flight_ms"} <= set(live_df.columns):
            di = live_df.dropna(subset=["flight_ms"]).copy()
            di["pair"] = di["prev_code"].astype(str) + "→" + di["code"].astype(str)
            for _, r in di.iterrows():
                p = r["pair"]
                fl = float(r["flight_ms"])
                if p in pair_stats:
                    mu = pair_stats[p]["mu"]
                    sd = max(pair_stats[p]["sd"], 1e-6)
                    z_list.append(abs((fl - mu) / sd))

        if z_list:
            z_aux = float(np.mean(z_list))
            aux_score = 1.0 / (1.0 + (z_aux / 2.0))  # z-score 기반(낮을수록 좋음)
        else:
            # 🔧 백업: 쌍글자 통계가 없으면 inlier_ratio를 그대로 보조점수로 사용
            # (이렇게 하면 76% 상한 고정이 사라지고, inlier 변화에 따라 점수가 자연스럽게 오르내립니다.)
            aux_score = inlier_ratio

        final = 0.6 * inlier_ratio + 0.4 * aux_score
        is_user = bool(final >= 0.65)

        return jsonify(
            {
                "is_user": is_user,
                "score": f"{final:.2%}",
                "score_num": round(final, 4),
                "parts": {
                    "inlier": round(inlier_ratio, 4),
                    "aux": round(aux_score, 4),
                },
            }
        )
    except Exception as e:
        app.logger.error(f"[{user}] verify 오류: {e}", exc_info=True)
        return jsonify(error=f"인증 중 서버 오류: {e}"), 500


# =========================================
# 에러 핸들러 / 실행
# =========================================
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify(error="Not Found"), 404
    return e, 404


@app.errorhandler(500)
def server_error(e):
    return jsonify(error="서버 내부 오류"), 500


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print(f"[DB] SQLite 초기화 완료: {DB_PATH}")
    app.run(host="0.0.0.0", port=5000, debug=True)
