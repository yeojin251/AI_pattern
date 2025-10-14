# model_trainer.py — Train IsolationForest for keystroke biometrics
# 사용법:
#   python model_trainer.py <username> [--min 200] [--contam 0.05]
#
# 특징:
# - analysis.py의 load_user_data가 있으면 우선 사용, 없으면 data_biometrics에서 직접 로드(FALLBACK)
# - user_profiles/<user>_profile.pkl (StandardScaler)가 없으면 자동 생성
# - dwell_ms, flight_ms만으로 학습 (실시간 검증 API와 동일)
# - 학습 리포트(훈련 inlier 비율)와 메타 JSON 저장

import os
import sys
import glob
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

DATA_DIR = "data_biometrics"
MODEL_DIR = "user_models"
PROFILE_DIR = "user_profiles"

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(PROFILE_DIR, exist_ok=True)

# -------------------- optional import --------------------
try:
    from analysis import load_user_data as _analysis_load_user_data  # type: ignore
except Exception:
    _analysis_load_user_data = None


def _fallback_load_user_data(username: str) -> pd.DataFrame | None:
    """analysis.load_user_data가 없을 때: data_biometrics의 해당 user CSV를 직접 로드."""
    pattern = os.path.join(DATA_DIR, f"{username}-*.csv")
    files = sorted(glob.glob(pattern))
    if not files:
        return None

    dfs = []
    for p in files:
        try:
            df = pd.read_csv(p)
            # 컬럼 표준화
            rename_map = {"dwell": "dwell_ms", "flight": "flight_ms"}
            df = df.rename(columns=rename_map)
            # 필요한 컬럼만 유지
            need = [c for c in ["dwell_ms", "flight_ms"] if c in df.columns]
            if not need:
                continue
            df = df[need]
            dfs.append(df)
        except Exception:
            pass
    if not dfs:
        return None
    out = pd.concat(dfs, ignore_index=True)
    # 숫자화/결측 제거
    for c in ["dwell_ms", "flight_ms"]:
        if c in out.columns:
            out[c] = pd.to_numeric(out[c], errors="coerce")
    out = out.dropna(subset=["dwell_ms", "flight_ms"])
    return out if len(out) else None


def load_user_data(username: str) -> pd.DataFrame | None:
    """우선 analysis.load_user_data 사용, 실패 시 fallback 로더 사용."""
    if _analysis_load_user_data is not None:
        try:
            df = _analysis_load_user_data(username)
            if df is not None and len(df):
                # 컬럼명 정규화
                rename_map = {"dwell": "dwell_ms", "flight": "flight_ms"}
                df = df.rename(columns=rename_map)
                for c in ["dwell_ms", "flight_ms"]:
                    if c in df.columns:
                        df[c] = pd.to_numeric(df[c], errors="coerce")
                df = df.dropna(subset=["dwell_ms", "flight_ms"])
                if len(df):
                    return df
        except Exception:
            pass
    return _fallback_load_user_data(username)


def _ensure_profile_scaler(username: str, df: pd.DataFrame) -> str:
    """프로필(표준화 스케일러) 없으면 생성해서 저장, 있으면 경로 반환."""
    profile_path = os.path.join(PROFILE_DIR, f"{username}_profile.pkl")
    if os.path.exists(profile_path):
        return profile_path

    features = ["dwell_ms", "flight_ms"]
    base = df[features].dropna()
    if len(base) < 50:
        raise RuntimeError("프로필 생성을 위한 데이터가 부족합니다. (>= 50)")

    scaler = StandardScaler()
    scaler.fit(base.values)

    payload = {
        "username": username,
        "scaler": scaler,
        "features": features,
        "created_at": pd.Timestamp.utcnow().isoformat(),
        "count": int(len(base)),
        "notes": "auto-created by model_trainer.py",
    }
    joblib.dump(payload, profile_path)
    return profile_path


def train_and_save_model(username: str, min_rows: int = 200, contamination: float = 0.05):
    print(f"[{username}] 모델 학습 준비…")

    # 1) 데이터 로드
    df = load_user_data(username)
    if df is None or len(df) < min_rows:
        print(f"오류: '{username}'의 유효 데이터가 부족합니다. (현재 {0 if df is None else len(df)}건, 최소 {min_rows}건 필요)")
        return

    # 2) 피처 선택
    features = ["dwell_ms", "flight_ms"]
    train_data = df[features].dropna()
    if len(train_data) < min_rows:
        print(f"오류: 결측 제거 후 학습 데이터가 부족합니다. (현재 {len(train_data)}건, 최소 {min_rows}건 필요)")
        return

    # 3) 스케일러 확보(없으면 자동 생성)
    profile_path = os.path.join(PROFILE_DIR, f"{username}_profile.pkl")
    if not os.path.exists(profile_path):
        print(f"[{username}] 프로필이 없어 자동 생성합니다.")
        profile_path = _ensure_profile_scaler(username, df)

    profile = joblib.load(profile_path)
    scaler: StandardScaler = profile["scaler"]

    # 4) 표준화
    X = scaler.transform(train_data.values)

    # 5) 모델 학습
    print(f"[{username}] IsolationForest 학습 시작… (rows={len(X)}, contamination={contamination})")
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)

    # 6) 저장
    model_path = os.path.join(MODEL_DIR, f"{username}_iforest_model.pkl")
    joblib.dump(model, model_path)

    # 7) 간단 리포트(훈련 데이터 inlier 비율)
    preds = model.predict(X)  # 1=inlier, -1=outlier
    inlier_ratio = float((preds == 1).sum()) / len(preds)
    print("-" * 60)
    print(f"모델 저장: {model_path}")
    print(f"프로필   : {profile_path}")
    print(f"훈련 데이터 inlier 비율: {inlier_ratio:.2%}")
    print("-" * 60)

    # 8) 메타 기록
    meta = {
        "username": username,
        "model_path": model_path,
        "profile_path": profile_path,
        "features": features,
        "rows": int(len(X)),
        "inlier_ratio_train": inlier_ratio,
        "contamination": contamination,
        "created_at": pd.Timestamp.utcnow().isoformat(),
        "notes": "IsolationForest; features=dwell_ms,flight_ms",
    }
    with open(os.path.splitext(model_path)[0] + ".meta.json", "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


def _parse_args(argv):
    # 간단한 파서 (argparse 없이)
    if len(argv) < 2:
        print("오류: 사용자 이름을 지정해야 합니다.")
        print("사용 예시: python model_trainer.py jsdky1234 --min 200 --contam 0.05")
        sys.exit(1)
    username = argv[1]
    min_rows = 200
    contamination = 0.05
    i = 2
    while i < len(argv):
        if argv[i] == "--min" and i + 1 < len(argv):
            min_rows = int(argv[i + 1]); i += 2
        elif argv[i] in ("--contam", "--contamination") and i + 1 < len(argv):
            contamination = float(argv[i + 1]); i += 2
        else:
            i += 1
    return username, min_rows, contamination


if __name__ == "__main__":
    user, min_rows, contam = _parse_args(sys.argv)
    train_and_save_model(user, min_rows=min_rows, contamination=contam)
