"""Random Forest risk classifier with persistence and per-prediction explanation."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from features import FEATURE_NAMES


MODEL_FILENAME = "rf_model.joblib"
META_FILENAME = "rf_meta.json"


@dataclass
class ModelMeta:
    model_version: str = "1.0.0"
    trained_at: str = ""
    n_samples: int = 0
    n_features: int = 0
    feature_names: List[str] = field(default_factory=list)
    training_sources: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    hyperparameters: Dict[str, Any] = field(default_factory=dict)


class RandomForestRiskModel:
    """Wrapper around sklearn RandomForestClassifier tailored to risk scoring."""

    def __init__(self, n_estimators: int = 200, max_depth: int = 12, random_state: int = 42):
        self.clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            class_weight="balanced",
            n_jobs=-1,
            random_state=random_state,
        )
        self.meta = ModelMeta(
            feature_names=list(FEATURE_NAMES),
            n_features=len(FEATURE_NAMES),
            hyperparameters={
                "n_estimators": n_estimators,
                "max_depth": max_depth,
                "class_weight": "balanced",
            },
        )

    def train(
        self,
        X: np.ndarray,
        y: np.ndarray,
        sources: Optional[List[str]] = None,
        test_size: float = 0.2,
    ) -> Dict[str, Any]:
        if X.shape[1] != len(FEATURE_NAMES):
            raise ValueError(
                f"Expected {len(FEATURE_NAMES)} features, got {X.shape[1]}"
            )
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, stratify=y, random_state=42
        )
        self.clf.fit(X_train, y_train)

        y_pred = self.clf.predict(X_test)
        y_proba = self.clf.predict_proba(X_test)[:, 1]

        metrics = {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "roc_auc": float(roc_auc_score(y_test, y_proba)),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
            "classification_report": classification_report(
                y_test, y_pred, output_dict=True, zero_division=0
            ),
            "feature_importance": dict(
                zip(FEATURE_NAMES, self.clf.feature_importances_.tolist())
            ),
        }
        self.meta.n_samples = int(X.shape[0])
        self.meta.trained_at = datetime.utcnow().isoformat() + "Z"
        self.meta.training_sources = sources or ["synthetic"]
        self.meta.metrics = metrics
        return metrics

    def predict_proba(self, x: np.ndarray) -> float:
        if x.ndim == 1:
            x = x.reshape(1, -1)
        return float(self.clf.predict_proba(x)[0, 1])

    def explain(self, x: np.ndarray, top_k: int = 5) -> List[Dict[str, Any]]:
        """Per-prediction explanation via feature-importance weighted contribution."""
        if x.ndim == 2:
            x = x[0]
        imp = self.clf.feature_importances_
        contrib = imp * x
        order = np.argsort(-np.abs(contrib))[:top_k]
        return [
            {
                "feature": FEATURE_NAMES[int(i)],
                "value": float(x[int(i)]),
                "importance": float(imp[int(i)]),
                "contribution": float(contrib[int(i)]),
            }
            for i in order
        ]

    def save(self, model_dir: str) -> None:
        os.makedirs(model_dir, exist_ok=True)
        joblib.dump(self.clf, os.path.join(model_dir, MODEL_FILENAME))
        with open(os.path.join(model_dir, META_FILENAME), "w") as f:
            json.dump(asdict(self.meta), f, indent=2)

    @classmethod
    def load(cls, model_dir: str) -> "RandomForestRiskModel":
        model_path = os.path.join(model_dir, MODEL_FILENAME)
        meta_path = os.path.join(model_dir, META_FILENAME)
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"No trained model at {model_path}")
        inst = cls()
        inst.clf = joblib.load(model_path)
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                data = json.load(f)
            inst.meta = ModelMeta(**data)
        return inst

    def top_features(self, k: int = 5) -> List[Tuple[str, float]]:
        imp = self.clf.feature_importances_
        order = np.argsort(-imp)[:k]
        return [(FEATURE_NAMES[int(i)], float(imp[int(i)])) for i in order]
