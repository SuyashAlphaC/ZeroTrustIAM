# Offline pytest suite for SQLite TrainingDataset (add_sample, stats, threading, as_dataframe).

from __future__ import annotations

import os
import tempfile
import threading

import numpy as np
import pandas as pd

from dataset import TrainingDataset
from features import FEATURE_NAMES


def _vec(i: int):
    base = [0.01 * ((i + j * 3) % 7) for j in range(len(FEATURE_NAMES))]
    l2 = float(np.linalg.norm(np.asarray(base, dtype=np.float64)))
    if l2 > 1e-9:
        scale = min(1.0, 20.0 / l2)
        base = [float(v * scale) for v in base]
    return base


def test_add_sample_returns_incrementing_id():
    with tempfile.TemporaryDirectory() as td:
        ds = TrainingDataset(os.path.join(td, "db.sqlite"))
        i1 = ds.add_sample(_vec(0), 0)
        i2 = ds.add_sample(_vec(1), 1)
        assert i2 > i1


def test_count_reflects_adds():
    with tempfile.TemporaryDirectory() as td:
        ds = TrainingDataset(os.path.join(td, "db.sqlite"))
        ds.add_sample(_vec(2), 0)
        ds.add_sample(_vec(3), 1)
        assert ds.count() == 2
        assert ds.count(0) == 1
        assert ds.count(1) == 1


def test_stats_splits():
    with tempfile.TemporaryDirectory() as td:
        ds = TrainingDataset(os.path.join(td, "db.sqlite"))
        ds.add_sample(_vec(4), 0)
        ds.add_sample(_vec(5), 1)
        s = ds.stats()
        assert s["total"] == 2
        assert s["benign"] == 1
        assert s["attack"] == 1


def test_concurrent_writes_persist():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "c.sqlite")
        errors: list[BaseException] = []

        def worker(offset: int):
            try:
                ds = TrainingDataset(path)
                for j in range(100):
                    ds.add_sample(_vec(offset + j), j % 2, source="stress")
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(k * 1000,)) for k in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        ds = TrainingDataset(path)
        assert ds.count() == 1000


def test_as_dataframe_shape_and_dtypes():
    with tempfile.TemporaryDirectory() as td:
        ds = TrainingDataset(os.path.join(td, "db.sqlite"))
        ds.add_sample(_vec(6), 0)
        df = ds.as_dataframe()
        assert df.shape == (1, len(FEATURE_NAMES) + 1)
        assert list(df.columns) == list(FEATURE_NAMES) + ["label"]
        assert str(df["device_unknown"].dtype).startswith("float")
        assert df["label"].tolist() == [0]


def test_as_dataframe_empty_columns():
    with tempfile.TemporaryDirectory() as td:
        ds = TrainingDataset(os.path.join(td, "e.sqlite"))
        df = ds.as_dataframe()
        assert df.shape[0] == 0
        assert "label" in df.columns
