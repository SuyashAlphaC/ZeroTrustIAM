"""
Optional loader for the Risk-Based Authentication (RBA) public dataset.

The dataset (IEEE DataPort, Wiefling et al.) ships as a single CSV where each
row is an authentication attempt with device/location/time fields and an
is_attack_ip label. We project each row into the same 17-feature vector used
by the synthetic generator so the two sources can be concatenated directly.

If the CSV is absent we return an empty array rather than failing — training
must remain possible with synthetic data alone.
"""

from __future__ import annotations

import math
import os
from typing import Tuple

import numpy as np
import pandas as pd

from features import FEATURE_NAMES


def _clip01(x: float) -> float:
    return float(max(0.0, min(1.0, x)))


def load_rba(csv_path: str, max_rows: int = 100000) -> Tuple[np.ndarray, np.ndarray]:
    if not os.path.exists(csv_path):
        return np.zeros((0, 17), dtype=np.float32), np.zeros(0, dtype=np.int32)

    usecols_candidates = [
        "Login Timestamp",
        "User ID",
        "Country",
        "Region",
        "City",
        "Device Type",
        "OS Name and Version",
        "Browser Name and Version",
        "Is Attack IP",
        "Login Successful",
    ]
    df = pd.read_csv(csv_path, nrows=max_rows, low_memory=False)
    keep = [c for c in usecols_candidates if c in df.columns]
    df = df[keep].copy()

    if "Login Timestamp" in df.columns:
        df["ts"] = pd.to_datetime(df["Login Timestamp"], errors="coerce", utc=True)
    else:
        df["ts"] = pd.Timestamp.utcnow()
    df = df.dropna(subset=["ts"])

    df["hour"] = df["ts"].dt.hour + df["ts"].dt.minute / 60.0
    df["dow"] = df["ts"].dt.weekday.astype(float) / 6.0

    user_col = "User ID" if "User ID" in df.columns else None
    country_col = "Country" if "Country" in df.columns else None
    city_col = "City" if "City" in df.columns else None
    device_col = "Device Type" if "Device Type" in df.columns else None

    if user_col:
        home_country = df.groupby(user_col)[country_col].agg(
            lambda s: s.mode().iloc[0] if not s.mode().empty else "UNKNOWN"
        ) if country_col else None
        home_city = df.groupby(user_col)[city_col].agg(
            lambda s: s.mode().iloc[0] if not s.mode().empty else "UNKNOWN"
        ) if city_col else None
        known_devices = df.groupby(user_col)[device_col].agg(set) if device_col else None
    else:
        home_country = home_city = known_devices = None

    n = len(df)
    X = np.zeros((n, 17), dtype=np.float32)
    y = np.zeros(n, dtype=np.int32)

    for i, row in enumerate(df.itertuples(index=False)):
        rec = row._asdict() if hasattr(row, "_asdict") else dict(zip(df.columns, row))
        user = rec.get(user_col) if user_col else None
        country = rec.get(country_col, "UNKNOWN") if country_col else "UNKNOWN"
        city = rec.get(city_col, "UNKNOWN") if city_col else "UNKNOWN"
        device = rec.get(device_col, "unknown") if device_col else "unknown"

        hc = home_country[user] if (home_country is not None and user in home_country.index) else country
        hci = home_city[user] if (home_city is not None and user in home_city.index) else city
        kd = known_devices[user] if (known_devices is not None and user in known_devices.index) else set()

        country_mismatch = 1 if country != hc else 0
        city_mismatch = 0 if country_mismatch else (1 if city != hci else 0)
        device_unknown = 0 if device in kd else 1
        device_novelty = device_unknown

        hour = float(rec.get("hour", 12.0))
        off_hours = 0 if 9 <= hour < 18 else 1
        hour_sin = math.sin(2 * math.pi * hour / 24)
        hour_cos = math.cos(2 * math.pi * hour / 24)
        dow = float(rec.get("dow", 0.0))

        is_attack = int(rec.get("Is Attack IP", 0) or 0)
        login_ok = int(rec.get("Login Successful", 1) or 0)
        failed_norm = 0.0 if login_ok else 0.2

        anomaly_combined = _clip01(
            0.25 * country_mismatch + 0.15 * device_novelty + 0.1 * off_hours
        )

        X[i] = [
            device_unknown,
            device_novelty,
            country_mismatch,
            city_mismatch,
            country_mismatch,  # location_novelty proxy
            0,                 # impossible travel not directly derivable per-row
            0.0,
            off_hours,
            hour_sin,
            hour_cos,
            dow,
            failed_norm,
            0.0,
            anomaly_combined,
            0,                 # is_privileged_op — unknown in RBA
            0.5,               # profile maturity proxy
            0,                 # ip_is_private — unknown
        ]
        y[i] = is_attack

    return X, y
