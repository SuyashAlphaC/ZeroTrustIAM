"""
SQLite-backed store for real labeled login samples.

Each row captures one ingested feature vector with a derived or observed label
(0 = benign, 1 = attack). The training pipeline consumes only this live store
so the Random Forest learns from observed production traffic.
"""

from __future__ import annotations

import json
import os
import random
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional, Tuple

import numpy as np

from features import FEATURE_NAMES


DEFAULT_DB_PATH = os.environ.get("ML_DATASET_PATH", "./models/training_samples.db")
ML_MAX_FEATURE_L2 = float(os.environ.get("ML_MAX_FEATURE_L2", "25"))
# Probability that a newly-ingested sample is held out for validation.
ML_VALIDATION_SPLIT = float(os.environ.get("ML_VALIDATION_SPLIT", "0.15"))
# Seed for the deterministic split assignment PRNG (tests rely on this).
ML_SPLIT_SEED = int(os.environ.get("ML_SPLIT_SEED", "1337"))


_SCHEMA = """
CREATE TABLE IF NOT EXISTS training_samples (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  features    TEXT    NOT NULL,
  label       INTEGER NOT NULL CHECK(label IN (0, 1)),
  source      TEXT    NOT NULL DEFAULT 'live',
  username    TEXT,
  decision    TEXT,
  reason      TEXT,
  audit_id    TEXT,
  label_source TEXT NOT NULL DEFAULT 'auto',
  split       TEXT NOT NULL DEFAULT 'train',
  created_at  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_created  ON training_samples(created_at);
CREATE INDEX IF NOT EXISTS idx_samples_label    ON training_samples(label);
CREATE INDEX IF NOT EXISTS idx_samples_source   ON training_samples(source);

CREATE TABLE IF NOT EXISTS retrain_runs (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at      TEXT NOT NULL,
  finished_at     TEXT,
  n_real          INTEGER,
  n_synthetic     INTEGER,
  accuracy        REAL,
  roc_auc         REAL,
  training_sources TEXT,
  status          TEXT NOT NULL,
  error           TEXT
);

CREATE TABLE IF NOT EXISTS model_baselines (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  recorded_at     TEXT NOT NULL,
  baseline_auc    REAL NOT NULL,
  window_days     INTEGER NOT NULL DEFAULT 7,
  notes           TEXT
);
"""


# Columns we add post-hoc; ALTER TABLE in older sqlite doesn't support
# IF NOT EXISTS, so we probe pragma_table_info first.
_ALTER_COLUMNS = (
    ("audit_id", "TEXT"),
    ("label_source", "TEXT NOT NULL DEFAULT 'auto'"),
    ("split", "TEXT NOT NULL DEFAULT 'train'"),
)


class TrainingDataset:
    """Thread-safe SQLite store for live training samples."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._split_rng = random.Random(ML_SPLIT_SEED)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            self._migrate_columns(conn)
            # Indexes that depend on migrated columns (safe after ALTER)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_samples_audit_id ON training_samples(audit_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_samples_split ON training_samples(split)"
            )
            conn.commit()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
        finally:
            conn.close()

    def _migrate_columns(self, conn: sqlite3.Connection) -> None:
        """Add new columns to legacy tables when missing (idempotent)."""
        cur = conn.execute("PRAGMA table_info(training_samples)")
        existing = {row[1] for row in cur.fetchall()}
        for name, ddl in _ALTER_COLUMNS:
            if name not in existing:
                conn.execute(
                    f"ALTER TABLE training_samples ADD COLUMN {name} {ddl}"
                )

    def _assign_split(self) -> str:
        """Deterministic train/validation assignment via seeded PRNG."""
        if ML_VALIDATION_SPLIT <= 0:
            return "train"
        if ML_VALIDATION_SPLIT >= 1:
            return "validation"
        return "validation" if self._split_rng.random() < ML_VALIDATION_SPLIT else "train"

    def add_sample(
        self,
        features: List[float],
        label: int,
        source: str = "live",
        username: Optional[str] = None,
        decision: Optional[str] = None,
        reason: Optional[str] = None,
        audit_id: Optional[str] = None,
        label_source: str = "auto",
        split: Optional[str] = None,
    ) -> int:
        if len(features) != len(FEATURE_NAMES):
            raise ValueError(
                f"Expected {len(FEATURE_NAMES)} features, got {len(features)}"
            )
        if label not in (0, 1):
            raise ValueError("label must be 0 or 1")
        arr = np.asarray(features, dtype=np.float64)
        l2 = float(np.linalg.norm(arr))
        if l2 > ML_MAX_FEATURE_L2:
            raise ValueError(
                f"feature L2 norm {l2:.2f} exceeds ML_MAX_FEATURE_L2={ML_MAX_FEATURE_L2} (possible poisoning)"
            )
        payload = json.dumps([float(v) for v in features])
        ts = datetime.utcnow().isoformat() + "Z"
        with self._lock, self._connect() as conn:
            assigned_split = split if split in ("train", "validation") else self._assign_split()
            cur = conn.execute(
                "INSERT INTO training_samples"
                "(features, label, source, username, decision, reason, audit_id, label_source, split, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    payload,
                    label,
                    source,
                    username,
                    decision,
                    reason,
                    audit_id,
                    label_source,
                    assigned_split,
                    ts,
                ),
            )
            conn.commit()
            return int(cur.lastrowid)

    def relabel_sample(
        self, audit_id: str, label: int, reviewer: str
    ) -> int:
        """Update a sample's label based on analyst feedback. Returns rows updated."""
        if label not in (0, 1):
            raise ValueError("label must be 0 or 1")
        if not audit_id:
            raise ValueError("audit_id is required")
        new_source = f"analyst:{reviewer}"
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE training_samples SET label=?, source=?, label_source=? WHERE audit_id=?",
                (label, new_source, "analyst", audit_id),
            )
            conn.commit()
            return int(cur.rowcount or 0)

    def count(self, label: Optional[int] = None) -> int:
        q = "SELECT COUNT(*) FROM training_samples"
        args: Tuple[Any, ...] = ()
        if label is not None:
            q += " WHERE label = ?"
            args = (label,)
        with self._connect() as conn:
            (n,) = conn.execute(q, args).fetchone()
            return int(n)

    def stats(self) -> Dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM training_samples").fetchone()[0]
            benign = conn.execute(
                "SELECT COUNT(*) FROM training_samples WHERE label = 0"
            ).fetchone()[0]
            attack = conn.execute(
                "SELECT COUNT(*) FROM training_samples WHERE label = 1"
            ).fetchone()[0]
            latest = conn.execute(
                "SELECT created_at FROM training_samples ORDER BY id DESC LIMIT 1"
            ).fetchone()
            earliest = conn.execute(
                "SELECT created_at FROM training_samples ORDER BY id ASC LIMIT 1"
            ).fetchone()
            sources = dict(
                conn.execute(
                    "SELECT source, COUNT(*) FROM training_samples GROUP BY source"
                ).fetchall()
            )
            label_sources = dict(
                conn.execute(
                    "SELECT label_source, COUNT(*) FROM training_samples GROUP BY label_source"
                ).fetchall()
            )
            splits = dict(
                conn.execute(
                    "SELECT split, COUNT(*) FROM training_samples GROUP BY split"
                ).fetchall()
            )
            last_run = conn.execute(
                "SELECT started_at, finished_at, n_real, n_synthetic, accuracy, roc_auc, training_sources, status, error "
                "FROM retrain_runs ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return {
            "total": int(total),
            "benign": int(benign),
            "attack": int(attack),
            "attack_rate": float(attack / total) if total else 0.0,
            "earliest": earliest[0] if earliest else None,
            "latest": latest[0] if latest else None,
            "by_source": sources,
            "by_label_source": label_sources,
            "by_split": splits,
            "last_retrain": (
                {
                    "started_at": last_run[0],
                    "finished_at": last_run[1],
                    "n_real": last_run[2],
                    "n_synthetic": last_run[3],
                    "accuracy": last_run[4],
                    "roc_auc": last_run[5],
                    "training_sources": json.loads(last_run[6]) if last_run[6] else None,
                    "status": last_run[7],
                    "error": last_run[8],
                }
                if last_run
                else None
            ),
        }

    def fetch_all(self) -> Tuple[np.ndarray, np.ndarray]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT features, label FROM training_samples"
            ).fetchall()
        return self._rows_to_arrays(rows)

    def fetch_train(self) -> Tuple[np.ndarray, np.ndarray]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT features, label FROM training_samples WHERE split = 'train'"
            ).fetchall()
        return self._rows_to_arrays(rows)

    def fetch_validation(self) -> Tuple[np.ndarray, np.ndarray]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT features, label FROM training_samples WHERE split = 'validation'"
            ).fetchall()
        return self._rows_to_arrays(rows)

    def fetch_recent_features(
        self, since_iso: str, limit: int = 5000
    ) -> np.ndarray:
        """Return the feature matrix for samples with created_at >= since_iso (newest first, capped)."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT features FROM training_samples WHERE created_at >= ? "
                "ORDER BY id DESC LIMIT ?",
                (since_iso, int(limit)),
            ).fetchall()
        if not rows:
            return np.zeros((0, len(FEATURE_NAMES)), dtype=np.float32)
        return np.asarray(
            [json.loads(r[0]) for r in rows], dtype=np.float32
        )

    def fetch_features_between(
        self, start_iso: str, end_iso: str, limit: int = 20000
    ) -> np.ndarray:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT features FROM training_samples WHERE created_at >= ? AND created_at < ? "
                "ORDER BY id DESC LIMIT ?",
                (start_iso, end_iso, int(limit)),
            ).fetchall()
        if not rows:
            return np.zeros((0, len(FEATURE_NAMES)), dtype=np.float32)
        return np.asarray(
            [json.loads(r[0]) for r in rows], dtype=np.float32
        )

    @staticmethod
    def _rows_to_arrays(rows) -> Tuple[np.ndarray, np.ndarray]:
        if not rows:
            return (
                np.zeros((0, len(FEATURE_NAMES)), dtype=np.float32),
                np.zeros((0,), dtype=np.int32),
            )
        X = np.asarray([json.loads(r[0]) for r in rows], dtype=np.float32)
        y = np.asarray([r[1] for r in rows], dtype=np.int32)
        return X, y

    def as_dataframe(self):
        """Return all samples as a DataFrame with FEATURE_NAMES columns plus ``label``."""
        import pandas as pd

        X, y = self.fetch_all()
        if X.shape[0] == 0:
            return pd.DataFrame(columns=list(FEATURE_NAMES) + ["label"])
        df = pd.DataFrame(X, columns=list(FEATURE_NAMES))
        df["label"] = y.astype(np.int64)
        return df

    def record_retrain_start(
        self, n_real: int, n_synthetic: int
    ) -> int:
        ts = datetime.utcnow().isoformat() + "Z"
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO retrain_runs(started_at, n_real, n_synthetic, status) VALUES (?, ?, ?, 'running')",
                (ts, n_real, n_synthetic),
            )
            conn.commit()
            return int(cur.lastrowid)

    def record_retrain_finish(
        self,
        run_id: int,
        accuracy: float,
        roc_auc: float,
        training_sources: List[str],
    ) -> None:
        ts = datetime.utcnow().isoformat() + "Z"
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE retrain_runs SET finished_at=?, accuracy=?, roc_auc=?, training_sources=?, status='success' WHERE id=?",
                (ts, accuracy, roc_auc, json.dumps(training_sources), run_id),
            )
            conn.commit()

    def record_retrain_error(self, run_id: int, error: str) -> None:
        ts = datetime.utcnow().isoformat() + "Z"
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE retrain_runs SET finished_at=?, status='error', error=? WHERE id=?",
                (ts, error[:500], run_id),
            )
            conn.commit()

    # ──────── Baseline AUC tracking (Tier B.7 auto-rollback) ────────

    def record_baseline_auc(self, auc: float, window_days: int = 7, notes: str = "") -> int:
        ts = datetime.utcnow().isoformat() + "Z"
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO model_baselines(recorded_at, baseline_auc, window_days, notes) VALUES (?, ?, ?, ?)",
                (ts, float(auc), int(window_days), notes or None),
            )
            conn.commit()
            return int(cur.lastrowid)

    def get_latest_baseline(self) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id, recorded_at, baseline_auc, window_days, notes FROM model_baselines ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if not row:
            return None
        return {
            "id": row[0],
            "recorded_at": row[1],
            "baseline_auc": float(row[2]),
            "window_days": int(row[3]),
            "notes": row[4],
        }
