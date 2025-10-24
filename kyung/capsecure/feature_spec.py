# feature_spec.py
import numpy as np
import pandas as pd

FEATURE_NAMES = [
    "dwell_ms_clip","flight_ms_clip","pause_flag",
    "is_backspace","is_char","hold_ratio","dt_ms_clip"
]

def build_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # 안전한 숫자화
    for c in ["dwell_ms","flight_ms","ts_down"]:
        if c in df:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    # 1) dwell, flight clip
    dwell = df["dwell_ms"].fillna(0.0)
    flight = df["flight_ms"].fillna(0.0)

    df["dwell_ms_clip"]  = dwell.clip(lower=20, upper=400)
    df["flight_ms_clip"] = flight.clip(lower=0,  upper=600)

    # 2) pause flag
    df["pause_flag"] = (df["flight_ms"].fillna(0.0) > 500).astype(int)

    # 3) key 종류
    codestr = df["code"].astype(str) if "code" in df else ""
    df["is_backspace"] = (codestr == "Key.backspace").astype(int)
    df["is_char"]      = codestr.str.startswith("Char.").astype(int)

    # 4) hold ratio
    df["hold_ratio"] = dwell / (dwell + flight.replace(0, np.nan).fillna(1.0))

    # 5) dt_ms (이전 ts_down과의 간격)
    if "ts_down" in df:
        ts = df["ts_down"].fillna(method="ffill")
        dt = ts.diff().fillna(ts.iloc[0] * 0)  # 첫 샘플은 0
        df["dt_ms_clip"] = dt.clip(lower=10, upper=800)
    else:
        df["dt_ms_clip"] = 400.0  # 적당한 기본값

    # 최종 선택
    return df[FEATURE_NAMES]