"""
Population Stability Index (PSI) feature-drift detection (Tier B.8).

PSI compares the distribution of each feature in a recent ("current") window
against an older ("baseline") window. Bins are derived from the baseline
quantiles so the metric is invariant to feature scale. We expose:

  * compute_psi  — per-feature PSI for two 1-D arrays
  * compute_drift — pulls samples from the live dataset and reports per-feature
    PSI plus an overall status bucket consumable by alerting / Grafana.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict

import numpy as np

from features import FEATURE_NAMES


_EPS = 1e-4

# Status thresholds (max PSI across all features).
_STATUS_THRESHOLDS = (
    (0.10, "stable"),
    (0.20, "minor"),
    (0.25, "significant"),
)


def compute_psi(reference: np.ndarray, current: np.ndarray, n_bins: int = 10) -> float:
    """Standard PSI between two 1-D distributions. Returns 0.0 on degenerate input."""
    ref = np.asarray(reference, dtype=np.float64).ravel()
    cur = np.asarray(current, dtype=np.float64).ravel()
    if ref.size == 0 or cur.size == 0:
        return 0.0

    # Decile cutpoints from the reference distribution.
    quantiles = np.linspace(0, 100, n_bins + 1)
    edges = np.percentile(ref, quantiles)
    # Collapse duplicate edges (constant features) so np.digitize is monotonic.
    edges = np.unique(edges)
    if edges.size <= 1:
        return 0.0
    # Wide-open the outer edges so values outside the reference range still bin.
    edges[0] = -np.inf
    edges[-1] = np.inf

    ref_counts, _ = np.histogram(ref, bins=edges)
    cur_counts, _ = np.histogram(cur, bins=edges)

    ref_pct = ref_counts.astype(np.float64) / max(ref.size, 1)
    cur_pct = cur_counts.astype(np.float64) / max(cur.size, 1)
    ref_pct = np.where(ref_pct == 0, _EPS, ref_pct)
    cur_pct = np.where(cur_pct == 0, _EPS, cur_pct)

    return float(np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct)))


def _classify(max_psi: float) -> str:
    for threshold, label in _STATUS_THRESHOLDS:
        if max_psi < threshold:
            return label
    return "critical"


def compute_drift(
    dataset: Any, days_baseline: int = 7, days_current: int = 1
) -> Dict[str, Any]:
    """Compute per-feature PSI from the live dataset.

    The dataset doesn't carry a clean per-window split, so we approximate by
    treating the most recent ~days_current/(days_baseline+days_current) fraction
    of samples as the "current" window. With tiny datasets the result is noisy
    by design — callers should bucket the status into the alerting tiers.
    """
    X, _ = dataset.fetch_all()
    n = int(X.shape[0])
    if n < 50:
        return {
            "features": {},
            "status": "insufficient_data",
            "n_samples": n,
            "computed_at": datetime.utcnow().isoformat() + "Z",
        }

    # Last `current_n` rows are "current"; preceding rows form the baseline.
    total_window = max(days_baseline + days_current, 1)
    current_n = max(int(n * days_current / total_window), 1)
    current_n = min(current_n, n - 1)
    baseline = X[: n - current_n]
    current = X[n - current_n :]

    features: Dict[str, float] = {}
    for idx, name in enumerate(FEATURE_NAMES):
        features[name] = compute_psi(baseline[:, idx], current[:, idx])

    max_psi = max(features.values()) if features else 0.0
    return {
        "features": features,
        "max_psi": float(max_psi),
        "status": _classify(max_psi),
        "computed_at": datetime.utcnow().isoformat() + "Z",
        "n_baseline": int(baseline.shape[0]),
        "n_current": int(current.shape[0]),
    }
