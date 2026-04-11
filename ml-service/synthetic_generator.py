"""
Synthetic training-data generator.

Produces a balanced set of benign and attack samples shaped as the 17-feature
vector used by the model. Five attack profiles are sampled with configurable
mix. Using the same FEATURE_NAMES ordering as features.py is essential — the
model cares only about the column index, not the name.
"""

from __future__ import annotations

import math
from typing import Tuple

import numpy as np

from features import FEATURE_NAMES


ATTACK_PROFILES = [
    "stolen_credentials",
    "impossible_travel",
    "credential_stuffing",
    "off_hours_privilege",
    "insider_threat",
]


def _clip01(x: float) -> float:
    return float(max(0.0, min(1.0, x)))


def _benign_sample(rng: np.random.Generator) -> np.ndarray:
    hour = rng.normal(12.5, 2.5)
    hour = float(np.clip(hour, 0, 23.999))
    off_hours = 0 if 9 <= hour < 18 else int(rng.random() < 0.1)
    maturity = _clip01(rng.beta(5, 2))
    vec = [
        0,                                         # device_unknown
        0,                                         # device_novelty
        0,                                         # country_mismatch
        int(rng.random() < 0.05),                  # city_mismatch
        int(rng.random() < 0.03),                  # location_novelty
        0,                                         # impossible_travel
        _clip01(rng.normal(0.02, 0.01)),           # travel_speed_norm
        off_hours,
        math.sin(2 * math.pi * hour / 24),
        math.cos(2 * math.pi * hour / 24),
        float(rng.integers(0, 5)) / 6.0,           # weekday bias
        _clip01(rng.normal(0.05, 0.05)),           # failed_attempts_norm
        _clip01(rng.normal(0.1, 0.1)),             # time_anomaly
        0.0,                                       # anomaly_combined (filled below)
        int(rng.random() < 0.2),                   # is_privileged_op
        maturity,
        int(rng.random() < 0.4),                   # ip_is_private
    ]
    vec[13] = _clip01(
        0.15 * vec[12] + 0.25 * vec[4] + 0.25 * vec[5] + 0.15 * vec[1]
    )
    return np.asarray(vec, dtype=np.float32)


def _attack_sample(profile: str, rng: np.random.Generator) -> np.ndarray:
    hour = rng.uniform(0, 24)
    vec = _benign_sample(rng)

    if profile == "stolen_credentials":
        vec[0] = 1
        vec[1] = 1
        vec[4] = int(rng.random() < 0.6)
        vec[11] = _clip01(rng.uniform(0.3, 1.0))
    elif profile == "impossible_travel":
        vec[2] = 1
        vec[4] = 1
        vec[5] = 1
        vec[6] = _clip01(rng.uniform(0.9, 5.0))
        vec[0] = int(rng.random() < 0.4)
    elif profile == "credential_stuffing":
        vec[0] = int(rng.random() < 0.8)
        vec[11] = 1.0
        vec[16] = int(rng.random() < 0.2)
    elif profile == "off_hours_privilege":
        hour = float(rng.choice([0, 1, 2, 3, 4, 22, 23]))
        vec[7] = 1
        vec[8] = math.sin(2 * math.pi * hour / 24)
        vec[9] = math.cos(2 * math.pi * hour / 24)
        vec[14] = 1
        vec[12] = _clip01(rng.uniform(0.4, 1.0))
    elif profile == "insider_threat":
        vec[0] = 0
        vec[1] = 0
        vec[14] = 1
        vec[7] = int(rng.random() < 0.6)
        vec[12] = _clip01(rng.uniform(0.2, 0.8))
        if vec[7] == 1:
            hour = float(rng.choice([1, 2, 3, 23]))
            vec[8] = math.sin(2 * math.pi * hour / 24)
            vec[9] = math.cos(2 * math.pi * hour / 24)

    vec[13] = _clip01(
        0.15 * vec[12] + 0.25 * vec[4] + 0.25 * vec[5] + 0.15 * vec[1]
    )
    return vec


def generate(
    n_samples: int = 10000,
    benign_fraction: float = 0.6,
    seed: int = 42,
) -> Tuple[np.ndarray, np.ndarray]:
    assert len(FEATURE_NAMES) == 17
    rng = np.random.default_rng(seed)
    n_benign = int(n_samples * benign_fraction)
    n_attack = n_samples - n_benign

    X = np.zeros((n_samples, 17), dtype=np.float32)
    y = np.zeros(n_samples, dtype=np.int32)

    for i in range(n_benign):
        X[i] = _benign_sample(rng)
        y[i] = 0

    per_profile = max(n_attack // len(ATTACK_PROFILES), 1)
    idx = n_benign
    for profile in ATTACK_PROFILES:
        for _ in range(per_profile):
            if idx >= n_samples:
                break
            X[idx] = _attack_sample(profile, rng)
            y[idx] = 1
            idx += 1
    while idx < n_samples:
        X[idx] = _attack_sample(rng.choice(ATTACK_PROFILES), rng)
        y[idx] = 1
        idx += 1

    perm = rng.permutation(n_samples)
    return X[perm], y[perm]
