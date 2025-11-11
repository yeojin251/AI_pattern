# model_trainer.py — 7피처 기반 IsolationForest 학습 스크립트
# 요구 패키지: pandas, numpy, scikit-learn, joblib
import os
import sys
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# 공용 유틸/스펙
from analysis import load_user_data  # CSV 로딩/정제 (이미 프로젝트 내 사용 중)
from feature_spec import build_features, FEATURE_NAMES

MODEL_DIR = "user_models"
PROFILE_DIR = "user_profiles"
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(PROFILE_DIR, exist_ok=True)

MIN_SAMPLES = 100  # 결측 제거 후 학습에 필요한 최소 표본 수


def train_and_save_model(username: str):
    print(f"[{username}] 모델 학습 시작")

    # 1) 원천 데이터 로딩
    df = load_user_data(username)
    if df is None or len(df) == 0:
        print(f"[ERR] '{username}' 데이터가 없습니다.")
        return

    # 2) 7피처 생성
    X = build_features(df)
    # FEATURE_NAMES 순서로 정렬(누락은 드롭)
    X = X.reindex(columns=FEATURE_NAMES)
    before_drop = len(X)
    X = X.dropna()
    after_drop = len(X)

    print(f"[INFO] 10피처 생성 완료: 원본 {before_drop} → 유효 {after_drop} 행")
    print(f"[INFO] FEATURE_NAMES = {FEATURE_NAMES}")

    if len(X) < MIN_SAMPLES:
        print(f"[ERR] 유효 표본이 부족합니다 (>= {MIN_SAMPLES} 필요). 현재: {len(X)}")
        print(
            "[HINT] 수집을 더 하고, 앱에서 '수집 데이터 분석' 버튼(Analyze)을 먼저 눌러보세요."
        )
        return

    # 3) 스케일러 로드(7피처용) 또는 생성
    profile_path = os.path.join(PROFILE_DIR, f"{username}_profile.pkl")
    scaler: StandardScaler | None = None
    profile = None
    need_save_profile = False

    if os.path.exists(profile_path):
        try:
            profile = joblib.load(profile_path)
            scaler = profile.get("scaler", None)
            prof_feats = profile.get("feature_names", [])
            if scaler is None or list(prof_feats) != list(FEATURE_NAMES):
                print(f"[WARN] 기존 프로필이 10피처 스펙과 불일치 → 새로 생성합니다.")
                scaler = None
        except Exception as e:
            print(f"[WARN] 프로필 로드 실패({e}) → 새로 생성합니다.")
            scaler = None

    if scaler is None:
        scaler = StandardScaler().fit(X.values)
        profile = {
            "scaler": scaler,
            "feature_names": list(FEATURE_NAMES),
            "created_at": pd.Timestamp.utcnow().isoformat(),
            "count": int(len(X)),
        }
        need_save_profile = True

    if need_save_profile:
        joblib.dump(profile, profile_path)
        print(
            f"[PROFILE] 저장: {profile_path} (count={profile['count']}, features={profile['feature_names']})"
        )
    else:
        print(
            f"[PROFILE] 사용: {profile_path} (features={profile.get('feature_names')})"
        )

    # 4) 표준화 & 모델 학습
    Xz = scaler.transform(X.values)
    model = IsolationForest(
        n_estimators=300,
        contamination=0.08,  # 이상치 비율 추정치(데이터에 따라 조정)
        max_samples="auto",
        random_state=42,
        bootstrap=False,
        n_jobs=-1,
    )
    model.fit(Xz)

    # 5) 저장
    model_path = os.path.join(MODEL_DIR, f"{username}_iforest_model.pkl")
    joblib.dump(model, model_path)

    print("-" * 60)
    print(f"[OK] 모델 저장 완료: {model_path}")
    print(f"[OK] 표본 수: {len(X)} | 피처: {list(FEATURE_NAMES)}")
    print("-" * 60)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("사용법: python model_trainer.py <username>")
        sys.exit(1)
    user = sys.argv[1]
    train_and_save_model(user)
