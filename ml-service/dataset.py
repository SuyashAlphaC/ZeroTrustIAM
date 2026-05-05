"""
SQLite-backed store for real labeled login samples.

Each row captures one ingested feature vector with a derived or observed label
(0 = benign, 1 = attack). The training pipeline consumes only this live store
so the Random Forest learns from observed production traffic.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional, Tuple

import numpy as np

from features import FEATURE_NAMES


DEFAULT_DB_PATH = os.environ.get("ML_DATASET_PATH", "./models/training_samples.db")
ML_MAX_FEATURE_L2 = float(os.environ.get("ML_MAX_FEATURE_L2", "25"))


_SCHEMA = """
CREATE TABLE IF NOT EXISTS training_samples (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  features    TEXT    NOT NULL,
  label       INTEGER NOT NULL CHECK(label IN (0, 1)),
  source      TEXT    NOT NULL DEFAULT 'live',
  username    TEXT,
  decision    TEXT,
  reason      TEXT,
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
"""


class TrainingDataset:
    """Thread-safe SQLite store for live training samples."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
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

    def add_sample(
        self,
        features: List[float],
        label: int,
        source: str = "live",
        username: Optional[str] = None,
        decision: Optional[str] = None,
        reason: Optional[str] = None,
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
            cur = conn.execute(
                "INSERT INTO training_samples(features, label, source, username, decision, reason, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (payload, label, source, username, decision, reason, ts),
            )
            conn.commit()
            return int(cur.lastrowid)

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
        if not rows:
            return (
                np.zeros((0, len(FEATURE_NAMES)), dtype=np.float32),
                np.zeros((0,), dtype=np.int32),
            )
        X = np.asarray([json.loads(r[0]) for r in rows], dtype=np.float32)
        y = np.asarray([r[1] for r in rows], dtype=np.int32)
        return X, y

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
