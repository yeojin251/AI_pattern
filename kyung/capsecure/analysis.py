# analysis.py — 키보드 입력 패턴 분석 모듈 (강화판)
# 역할: 데이터 로딩, 특징 추출, 사용자 프로파일링(7피처), 시각화(확장)
# 요구 패키지: pandas, numpy, scikit-learn, joblib, matplotlib, seaborn

import os
import glob
import json
import numpy as np
import pandas as pd

import matplotlib
matplotlib.use("Agg")  # 서버/헤드리스 환경 안전
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib import font_manager, rcParams

from sklearn.preprocessing import StandardScaler
import joblib

# === 7개 피처 공용 스펙 ===
# 반드시 feature_spec.py의 FEATURE_NAMES와 동일하게 유지되어야 합니다.
from feature_spec import build_features, FEATURE_NAMES

# ============================ 한글 폰트 설정 ============================
def ensure_korean_font():
    """
    실행 환경에 맞는 한글 폰트를 자동 설정.
    1) ./fonts 폴더의 TTF/OTF 우선 (예: fonts/NanumGothic.ttf)
    2) 시스템 폰트 후보(Malgun Gothic, AppleGothic, NanumGothic, Noto Sans CJK KR)
    """
    # 1) 로컬 폰트 우선
    local_candidates = [
        "fonts/NanumGothic.ttf",
        "fonts/NotoSansKR-Regular.otf",
        "fonts/AppleGothic.ttf",
        "fonts/malgun.ttf",
    ]
    for p in local_candidates:
        if os.path.exists(p):
            try:
                font_manager.fontManager.addfont(p)
                rcParams["font.family"] = font_manager.FontProperties(fname=p).get_name()
                rcParams["axes.unicode_minus"] = False
                return
            except Exception:
                pass

    # 2) 시스템 폰트 후보
    system_candidates = [
        "Malgun Gothic",   # Windows
        "AppleGothic",     # macOS
        "NanumGothic",     # Linux (나눔고딕)
        "Noto Sans CJK KR" # 일부 리눅스/컨테이너
    ]
    available = {f.name for f in font_manager.fontManager.ttflist}
    for name in system_candidates:
        if name in available:
            rcParams["font.family"] = name
            rcParams["axes.unicode_minus"] = False
            return

    # 3) 폰트 미발견 시 경고 (플롯은 생성되지만 한글이 깨질 수 있음)
    print("[warn] 한글 폰트를 찾지 못했습니다. 프로젝트 fonts/ 폴더에 TTF/OTF를 넣어주세요.")
    rcParams["axes.unicode_minus"] = False

ensure_korean_font()

# ============================ 상수/경로 ============================
DATA_DIR    = "data_biometrics"
PROFILE_DIR = "user_profiles"
FIGURE_DIR  = "user_figures"
FEATURE_DIR = "user_features"  # 요약 피처 저장(선택)

os.makedirs(PROFILE_DIR, exist_ok=True)
os.makedirs(FIGURE_DIR,  exist_ok=True)
os.makedirs(FEATURE_DIR, exist_ok=True)

# ============================ 1) 데이터 로딩/정제 ============================
def load_user_data(username: str) -> pd.DataFrame | None:
    """
    특정 사용자의 모든 CSV를 로드/결합/정제.
    기대 컬럼: ts_down, ts_up, dwell_ms, flight_ms, code, prev_code, key
    """
    files = glob.glob(os.path.join(DATA_DIR, f"{username}-*.csv"))
    if not files:
        print(f"[load_user_data] '{username}' CSV가 없습니다.")
        return None

    dfs = []
    for f in files:
        try:
            df = pd.read_csv(f)
            # 구버전 컬럼명 보정
            df = df.rename(columns={"dwell": "dwell_ms", "flight": "flight_ms"})
            # 수치형 변환
            for c in ["ts_down", "ts_up", "dwell_ms", "flight_ms"]:
                if c in df.columns:
                    df[c] = pd.to_numeric(df[c], errors="coerce")
            dfs.append(df)
        except Exception as e:
            print(f"[load_user_data] '{f}' 로드 실패: {e}")

    if not dfs:
        return None

    full = pd.concat(dfs, ignore_index=True)

    # 필수 컬럼 체크
    needed = {"ts_down", "ts_up", "dwell_ms", "code"}
    if not needed.issubset(full.columns):
        print(f"[load_user_data] 필수 컬럼 누락: {needed - set(full.columns)}")
        return None

    # 기본 정제
    full = full.dropna(subset=["ts_down", "ts_up", "dwell_ms"])

    # flight_ms 음수 제거(오버랩은 0 처리)
    if "flight_ms" in full.columns:
        full["flight_ms"] = pd.to_numeric(full["flight_ms"], errors="coerce")
        full.loc[full["flight_ms"] < 0, "flight_ms"] = 0
    else:
        full["flight_ms"] = np.nan

    # 문자열 컬럼 정규화
    for c in ["code", "prev_code", "key"]:
        if c in full.columns:
            full[c] = full[c].astype(str)

    print(f"[load_user_data] '{username}' {len(full)}건 로드/정제 완료.")
    return full.reset_index(drop=True)

# ============================ 2) 특징 추출 ============================
def _is_char_series(code_series: pd.Series) -> pd.Series:
    """'Char.'로 시작하는 실제 문자 키 여부"""
    return code_series.astype(str).str.startswith("Char.")

def extract_global_features(df: pd.DataFrame, pause_thresh_ms: float = 500.0) -> dict:
    """세션 전체 전역 특징 (속도/오타/정지/리듬 등)"""
    feats: dict[str, float] = {}

    # 기본 통계
    dwell = pd.to_numeric(df["dwell_ms"], errors="coerce").dropna()
    flight = pd.to_numeric(df["flight_ms"], errors="coerce").dropna()

    def _stats(x: pd.Series) -> dict:
        if x.empty:
            return {"mean": 0.0, "std": 0.0, "median": 0.0, "iqr": 0.0}
        q1, q3 = x.quantile([0.25, 0.75])
        return {
            "mean": float(x.mean()),
            "std": float(x.std(ddof=1)) if len(x) > 1 else 0.0,
            "median": float(x.median()),
            "iqr": float(q3 - q1),
        }

    dw = _stats(dwell)
    fl = _stats(flight)
    feats.update({f"dwell_{k}": v for k, v in dw.items()})
    feats.update({f"flight_{k}": v for k, v in fl.items()})

    # 타이핑 속도 (KPS/CPM/WPM)
    dur_ms = float(df["ts_up"].max() - df["ts_down"].min()) if len(df) else 1.0
    kps = len(df) / (dur_ms / 1000.0)
    chars = _is_char_series(df["code"]).sum()
    cpm = 60000.0 * chars / dur_ms
    wpm = cpm / 5.0
    feats.update(
        {"typing_kps": float(kps), "typing_cpm": float(cpm), "typing_wpm": float(wpm)}
    )

    # Pause/Idle
    if "flight_ms" in df.columns and df["flight_ms"].notna().any():
        feats[f"pause_rate_gt{int(pause_thresh_ms)}ms"] = float(
            (df["flight_ms"] > pause_thresh_ms).mean()
        )
        feats["longest_pause_ms"] = float(df["flight_ms"].max())
    else:
        feats[f"pause_rate_gt{int(pause_thresh_ms)}ms"] = 0.0
        feats["longest_pause_ms"] = 0.0

    # Backspace 패턴
    if "code" in df.columns:
        bs = (df["code"] == "Key.backspace").astype(int)
        feats["backspace_ratio"] = float(bs.mean())
        # 연속 버스트 길이
        bursts, run = [], 0
        for v in bs:
            if v == 1:
                run += 1
            elif run > 0:
                bursts.append(run)
                run = 0
        if run > 0:
            bursts.append(run)
        feats["backspace_burst_mean"] = float(np.mean(bursts)) if bursts else 0.0
        feats["backspace_burst_max"] = float(np.max(bursts)) if bursts else 0.0
    else:
        feats["backspace_ratio"] = 0.0
        feats["backspace_burst_mean"] = 0.0
        feats["backspace_burst_max"] = 0.0

    # Rhythm Consistency (변동성: coefficient of variation)
    def _cv(x: pd.Series) -> float:
        m = x.mean()
        return float(x.std(ddof=1) / m) if len(x) > 1 and m > 0 else 0.0

    feats["dwell_cv"] = _cv(dwell)
    feats["flight_cv"] = _cv(flight)

    return feats

def extract_ngram_features(
    df: pd.DataFrame, top_digraphs: int = 20, top_trigrams: int = 12
) -> dict:
    """N-gram 특징: Digram/Trigram의 평균/표준편차(고빈도 상위만)"""
    out: dict[str, float] = {}

    # Digram
    if {"prev_code", "code", "flight_ms"} <= set(df.columns):
        x = df.dropna(subset=["flight_ms"]).copy()
        x["pair"] = x["prev_code"].astype(str) + "→" + x["code"].astype(str)
        cnt = x["pair"].value_counts().head(top_digraphs)
        for p in cnt.index:
            s = pd.to_numeric(
                x.loc[x["pair"] == p, "flight_ms"], errors="coerce"
            ).dropna()
            if not s.empty:
                out[f"pair_flight_mean[{p}]"] = float(s.mean())
                out[f"pair_flight_std[{p}]"] = (
                    float(s.std(ddof=1)) if len(s) > 1 else 0.0
                )

    # Trigram(두 flight 평균 근사)
    if {"code", "flight_ms"} <= set(df.columns):
        tri = df[["code", "flight_ms"]].copy()
        tri["c1"] = tri["code"].shift(2)
        tri["c2"] = tri["code"].shift(1)
        tri["c3"] = tri["code"]
        tri["f12"] = pd.to_numeric(tri["flight_ms"].shift(1), errors="coerce")
        tri["f23"] = pd.to_numeric(tri["flight_ms"], errors="coerce")
        tri = tri.dropna(subset=["c1", "c2", "c3", "f12", "f23"])
        tri["tri"] = (
            tri["c1"].astype(str) + "→" + tri["c2"].astype(str) + "→" + tri["c3"].astype(str)
        )
        tri["tri_time"] = (tri["f12"] + tri["f23"]) / 2.0
        cnt = tri["tri"].value_counts().head(top_trigrams)
        for t in cnt.index:
            s = tri.loc[tri["tri"] == t, "tri_time"].dropna()
            if not s.empty:
                out[f"tri_time_mean[{t}]"] = float(s.mean())
                out[f"tri_time_std[{t}]"] = (
                    float(s.std(ddof=1)) if len(s) > 1 else 0.0
                )

    return out

def create_feature_vector(username: str) -> dict | None:
    """전역 특징 + N-gram 특징 합쳐 최종 벡터 생성"""
    df = load_user_data(username)
    if df is None or len(df) < 50:
        print(f"[create_feature_vector] '{username}' 데이터 부족")
        return None
    g = extract_global_features(df)
    n = extract_ngram_features(df)
    vec = {**g, **n}
    return pd.Series(vec, dtype="float64").fillna(0).to_dict()

# ============================ 3) 사용자 프로파일(7피처) ============================
def create_and_save_user_profile(username: str):
    """
    사용자 프로파일(표준화 스케일러)을 7개 피처(FEATURE_NAMES)로 생성/저장.
    - server.verify 및 model_trainer가 동일 피처 집합을 사용하므로 반드시 일치해야 함.
    """
    df = load_user_data(username)
    if df is None:
        print(f"[profile] '{username}' 데이터 없음")
        return

    # build_features로 7개 피처 생성
    X = build_features(df)

    # 컬럼 정렬/필수 보장: FEATURE_NAMES 순서로 재정렬 (누락 시 drop)
    X = X.reindex(columns=FEATURE_NAMES)

    # 학습에 사용할 유효 표본만 사용
    X = X.dropna()
    if len(X) < 100:
        print(f"[profile] 데이터 부족(>=100 필요). 현재 {len(X)}")
        return

    scaler = StandardScaler().fit(X.values)
    profile = {
        "scaler": scaler,
        "feature_names": list(X.columns),  # 반드시 FEATURE_NAMES와 동일
        "created_at": pd.Timestamp.utcnow().isoformat(),
        "count": int(len(X)),
    }

    os.makedirs(PROFILE_DIR, exist_ok=True)
    path = os.path.join(PROFILE_DIR, f"{username}_profile.pkl")
    joblib.dump(profile, path)
    print(f"[profile] 저장: {path} (features={list(X.columns)})")

# ============================ 4) 시각화(확장) ============================
def _rolling(series: pd.Series, window: int = 60):
    """결측/길이 짧음 방지 rolling 평균"""
    if series.isna().all() or len(series) == 0:
        return series
    w = min(window, max(1, len(series) // 10))
    return series.rolling(w, min_periods=max(1, w // 3)).mean()

def visualize_user_data(username: str, pause_thresh_ms: float = 500.0):
    """
    강화된 대시보드 PNG 1장 생성:
    - Dwell/Flight 분포
    - Rolling KPS, Dwell/Flight 평균(리듬)
    - Pause 분포/비율
    - Backspace 사용/버스트
    - N-gram(Digram) 상위 flight 평균 Bar (없으면 Per-key dwell 상위)
    """
    df = load_user_data(username)
    if df is None or len(df) < 10:
        print(f"[visualize] '{username}' 데이터 부족")
        return

    # 안전 전처리
    df["dwell_ms"] = pd.to_numeric(df["dwell_ms"], errors="coerce")
    df["flight_ms"] = pd.to_numeric(df["flight_ms"], errors="coerce")
    df = df.dropna(subset=["dwell_ms"])
    df = df.sort_values(["ts_down", "ts_up"]).reset_index(drop=True)

    # ===== 파생 시리즈 =====
    # 1) 시간대별 KPS(롤링)
    dt = pd.Series(np.diff(df["ts_down"], prepend=df["ts_down"].iloc[0]))
    dt.replace(0, np.nan, inplace=True)
    kps_inst = 1000.0 / dt  # 근사치
    kps_roll = _rolling(kps_inst, window=100)

    # 2) 리듬(롤링 평균)
    dw_roll = _rolling(df["dwell_ms"], window=120)
    fl_roll = _rolling(df["flight_ms"].fillna(method="ffill"), window=120)

    # 3) pause 분포
    flight_valid = df["flight_ms"].dropna()
    pause_rate = float((flight_valid > pause_thresh_ms).mean()) if not flight_valid.empty else 0.0

    # 4) backspace
    is_bs = (df["code"] == "Key.backspace").astype(int)
    bs_ratio = float(is_bs.mean())

    # 5) digram 상위
    dig_bar = None
    if {"prev_code", "code", "flight_ms"} <= set(df.columns):
        di = df.dropna(subset=["flight_ms"]).copy()
        di["pair"] = di["prev_code"].astype(str) + "→" + di["code"].astype(str)
        top_pairs = di["pair"].value_counts().head(12).index
        dig = (
            di[di["pair"].isin(top_pairs)]
            .groupby("pair")["flight_ms"]
            .mean()
            .sort_values(ascending=False)
        )
        dig_bar = dig

    # 6) per-key dwell 상위
    key_bar = (
        df.groupby("code")["dwell_ms"]
        .mean()
        .sort_values(ascending=False)
        .head(12)
    )

    # ===== 그림 =====
    sns.set_theme(style="whitegrid")
    fig = plt.figure(figsize=(18, 12))
    gs = fig.add_gridspec(3, 3)

    ax1 = fig.add_subplot(gs[0, 0])
    ax2 = fig.add_subplot(gs[0, 1])
    ax3 = fig.add_subplot(gs[0, 2])
    ax4 = fig.add_subplot(gs[1, 0])
    ax5 = fig.add_subplot(gs[1, 1])
    ax6 = fig.add_subplot(gs[1, 2])
    ax7 = fig.add_subplot(gs[2, 0])
    ax8 = fig.add_subplot(gs[2, 1])
    ax9 = fig.add_subplot(gs[2, 2])

    # 1) Dwell 분포
    sns.histplot(
        df["dwell_ms"].clip(upper=df["dwell_ms"].quantile(0.99)),
        bins=50, kde=True, ax=ax1
    )
    ax1.set_title("Dwell Time 분포 (상위 1% 컷)")
    ax1.set_xlabel("dwell (ms)")
    ax1.set_ylabel("빈도")

    # 2) Flight 분포
    if not flight_valid.empty:
        sns.histplot(
            flight_valid.clip(upper=flight_valid.quantile(0.99)),
            bins=50, kde=True, ax=ax2
        )
    ax2.set_title("Flight Time 분포 (상위 1% 컷)")
    ax2.set_xlabel("flight (ms)")
    ax2.set_ylabel("빈도")

    # 3) Pause 비율
    ax3.bar(["Pause Rate"], [pause_rate])
    ax3.set_ylim(0, 1)
    ax3.set_title(f"Pause 비율(>{int(pause_thresh_ms)}ms)")
    ax3.text(0, min(0.98, pause_rate + 0.02), f"{pause_rate:.1%}", ha="center")

    # 4) Rolling KPS
    ax4.plot(kps_roll.index, kps_roll.values)
    ax4.set_title("타이핑 속도 (Rolling KPS)")
    ax4.set_xlabel("event idx")
    ax4.set_ylabel("KPS")

    # 5) Rolling dwell
    ax5.plot(dw_roll.index, dw_roll.values)
    ax5.set_title("리듬: Dwell Rolling Mean")
    ax5.set_xlabel("event idx")
    ax5.set_ylabel("ms")

    # 6) Rolling flight
    if not fl_roll.isna().all():
        ax6.plot(fl_roll.index, fl_roll.values)
    ax6.set_title("리듬: Flight Rolling Mean")
    ax6.set_xlabel("event idx")
    ax6.set_ylabel("ms")

    # 7) Backspace 비율
    ax7.bar(["Backspace Ratio"], [bs_ratio])
    ax7.set_ylim(0, 1)
    ax7.set_title("Backspace 사용 비율")
    ax7.text(0, min(0.98, bs_ratio + 0.02), f"{bs_ratio:.1%}", ha="center")

    # 8) Backspace 버스트 분포
    bursts, run = [], 0
    for v in is_bs:
        if v == 1:
            run += 1
        elif run > 0:
            bursts.append(run)
            run = 0
    if run > 0:
        bursts.append(run)
    if bursts:
        sns.histplot(pd.Series(bursts), bins=range(1, max(bursts) + 2), ax=ax8, discrete=True)
        ax8.set_title("Backspace 연속 버스트 분포")
        ax8.set_xlabel("burst length")
        ax8.set_ylabel("count")
    else:
        ax8.text(0.5, 0.5, "버스트 없음", ha="center")
        ax8.set_axis_off()

    # 9) Digram flight 평균 상위 Bar (없으면 per-key dwell 상위로 대체)
    if dig_bar is not None and len(dig_bar):
        sns.barplot(x=dig_bar.values, y=dig_bar.index, ax=ax9, orient="h")
        ax9.set_title("상위 Digram Flight 평균")
        ax9.set_xlabel("mean flight (ms)")
        ax9.set_ylabel("digram")
    else:
        kb = key_bar
        sns.barplot(x=kb.values, y=kb.index, ax=ax9, orient="h")
        ax9.set_title("Per-Key Dwell 상위 평균")
        ax9.set_xlabel("mean dwell (ms)")
        ax9.set_ylabel("key")

    fig.suptitle(f"{username} — Keystroke Biometrics Dashboard", fontsize=16, y=0.995)
    fig.tight_layout(rect=[0, 0.01, 1, 0.97])

    os.makedirs(FIGURE_DIR, exist_ok=True)
    out_path = os.path.join(FIGURE_DIR, f"{username}_dashboard.png")
    fig.savefig(out_path, dpi=140)
    plt.close(fig)
    print(f"[visualize] 저장: {out_path}")

    # ===== 요약 표 저장(선택) =====
    gfeat = extract_global_features(df)
    nfeat = extract_ngram_features(df, top_digraphs=12, top_trigrams=8)
    summary = {**gfeat, **nfeat}
    os.makedirs(FEATURE_DIR, exist_ok=True)
    with open(os.path.join(FEATURE_DIR, f"{username}_features.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[visualize] 요약 특징 저장: {os.path.join(FEATURE_DIR, f'{username}_features.json')}")
