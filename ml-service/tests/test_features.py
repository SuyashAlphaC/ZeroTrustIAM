"""Unit tests for feature extraction hygiene."""

from __future__ import annotations

import numpy as np

from features import (
    FEATURE_NAMES,
    clip_feature_vector,
    extract_features,
    RequestContextModel,
    RiskRequest,
    UserProfileModel,
)


def test_clip_handles_nan_inf() -> None:
    raw = clip_feature_vector(np.array([np.nan, np.inf, -np.inf], dtype=np.float32))
    assert np.isfinite(raw).all()


def test_extract_features_bounded() -> None:
    req = RiskRequest(
        username="u",
        user_profile=UserProfileModel(profile_samples=0),
        request_context=RequestContextModel(timestamp="2026-01-01T12:00:00Z"),
    )
    x = extract_features(req)
    assert x.shape == (len(FEATURE_NAMES),)
    assert float(np.linalg.norm(np.clip(x, -10.0, 10.0) - x)) < 1e-6


def test_large_values_clipped_components() -> None:
    vec = clip_feature_vector(np.array([999.0, -888.0, 0.2], dtype=np.float32))
    assert vec.max() <= 10.0
    assert vec.min() >= -10.0
