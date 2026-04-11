"""
Feature extraction for the Zero Trust IAM risk model.

A login attempt arrives as a RiskRequest and is expanded into a fixed-length
feature vector. The feature set is intentionally a superset of what the
Node.js AHP scorer and anomaly detector already compute — the model re-uses
those signals rather than replacing them, so training data and inference
share identical feature semantics.
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import List, Optional

import numpy as np
from pydantic import BaseModel, Field


FEATURE_NAMES: List[str] = [
    "device_unknown",
    "device_novelty",
    "location_country_mismatch",
    "location_city_mismatch",
    "location_novelty",
    "impossible_travel",
    "travel_speed_kmh",
    "off_hours",
    "hour_of_day_sin",
    "hour_of_day_cos",
    "day_of_week",
    "failed_attempts_norm",
    "time_anomaly_z",
    "anomaly_combined",
    "is_privileged_op",
    "profile_maturity_norm",
    "ip_is_private",
]


class LocationModel(BaseModel):
    country: str = "UNKNOWN"
    city: str = "UNKNOWN"
    lat: Optional[float] = None
    lon: Optional[float] = None


class UserProfileModel(BaseModel):
    registered_devices: List[str] = Field(default_factory=list)
    usual_location: LocationModel = Field(default_factory=LocationModel)
    normal_hours: List[int] = Field(default_factory=lambda: [9, 18])
    known_locations: List[str] = Field(default_factory=list)
    known_devices: List[str] = Field(default_factory=list)
    login_hours_mean: float = 12.0
    login_hours_std: float = 4.0
    profile_samples: int = 0


class LastLoginModel(BaseModel):
    timestamp: Optional[str] = None
    location: Optional[LocationModel] = None


class RequestContextModel(BaseModel):
    device_id: str = "unknown"
    timestamp: str
    ip: str = "0.0.0.0"
    location: LocationModel = Field(default_factory=LocationModel)
    required_permission: str = "read"
    failed_attempts: int = 0
    last_login: Optional[LastLoginModel] = None


class RiskRequest(BaseModel):
    username: str
    user_profile: UserProfileModel
    request_context: RequestContextModel


PRIVILEGED_OPS = {"write", "delete", "admin", "approve", "sign", "issue", "revoke"}


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return datetime.utcnow()


def _is_private_ip(ip: str) -> int:
    if not ip or ip == "0.0.0.0":
        return 0
    parts = ip.split(".")
    if len(parts) != 4:
        return 0
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return 0
    if a == 10:
        return 1
    if a == 172 and 16 <= b <= 31:
        return 1
    if a == 192 and b == 168:
        return 1
    return 0


def extract_features(req: RiskRequest) -> np.ndarray:
    p = req.user_profile
    c = req.request_context

    device_unknown = 0 if c.device_id in p.registered_devices else 1
    device_novelty = 0 if c.device_id in set(p.known_devices) else 1 if p.known_devices else 0

    country_mismatch = 1 if c.location.country != p.usual_location.country else 0
    city_mismatch = (
        0
        if country_mismatch == 1
        else (1 if c.location.city != p.usual_location.city else 0)
    )

    loc_key = f"{c.location.country}:{c.location.city}"
    location_novelty = 0 if loc_key in set(p.known_locations) else 1 if p.known_locations else 0

    impossible_travel = 0
    travel_speed = 0.0
    if (
        c.last_login
        and c.last_login.timestamp
        and c.last_login.location
        and c.last_login.location.lat is not None
        and c.location.lat is not None
    ):
        last_t = _parse_ts(c.last_login.timestamp)
        now_t = _parse_ts(c.timestamp)
        hours = max((now_t - last_t).total_seconds() / 3600.0, 1e-6)
        dist_km = haversine_km(
            c.last_login.location.lat,
            c.last_login.location.lon or 0.0,
            c.location.lat,
            c.location.lon or 0.0,
        )
        travel_speed = dist_km / hours
        if travel_speed > 900.0:
            impossible_travel = 1

    dt = _parse_ts(c.timestamp)
    hour = dt.hour + dt.minute / 60.0
    start_h, end_h = p.normal_hours[0], p.normal_hours[1]
    off_hours = 0 if start_h <= hour < end_h else 1
    hour_sin = math.sin(2 * math.pi * hour / 24.0)
    hour_cos = math.cos(2 * math.pi * hour / 24.0)
    dow = float(dt.weekday())

    failed_norm = min(c.failed_attempts / 5.0, 1.0)

    if p.profile_samples >= 3 and p.login_hours_std > 0:
        z = abs(hour - p.login_hours_mean) / p.login_hours_std
        time_anomaly = min(z / 3.0, 1.0)
    else:
        time_anomaly = 0.0

    anomaly_combined = min(
        0.15 * time_anomaly
        + 0.25 * location_novelty
        + 0.25 * impossible_travel
        + 0.15 * device_novelty,
        1.0,
    )

    is_priv = 1 if c.required_permission in PRIVILEGED_OPS else 0
    maturity_norm = min(p.profile_samples / 50.0, 1.0)
    ip_private = _is_private_ip(c.ip)

    vec = [
        device_unknown,
        device_novelty,
        country_mismatch,
        city_mismatch,
        location_novelty,
        impossible_travel,
        min(travel_speed / 1000.0, 5.0),
        off_hours,
        hour_sin,
        hour_cos,
        dow / 6.0,
        failed_norm,
        time_anomaly,
        anomaly_combined,
        is_priv,
        maturity_norm,
        ip_private,
    ]
    return np.asarray(vec, dtype=np.float32)
