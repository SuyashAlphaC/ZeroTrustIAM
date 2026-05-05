"""CLI entry point for training the risk Random Forest."""

from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np

from dataset import TrainingDataset
from model import RandomForestRiskModel
from public_loader import load_rba


def main() -> int:
    ap = argparse.ArgumentParser(description="Train the Zero Trust IAM RF risk model")
    ap.add_argument("--dataset", type=str, default="./models/training_samples.db", help="Path to live SQLite training dataset")
    ap.add_argument("--public", type=str, default=None, help="Path to RBA CSV (optional)")
    ap.add_argument("--public-max-rows", type=int, default=100000)
    ap.add_argument("--model-dir", type=str, default="./models")
    ap.add_argument("--n-estimators", type=int, default=200)
    ap.add_argument("--max-depth", type=int, default=12)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    sources = []
    X_list, y_list = [], []

    if args.dataset:
        live_dataset = TrainingDataset(args.dataset)
        X_live, y_live = live_dataset.fetch_all()
        if X_live.shape[0] > 0:
            X_list.append(X_live)
            y_list.append(y_live)
            sources.append(f"live:{X_live.shape[0]}")
            print(f"[train] live: {X_live.shape[0]} samples (attack rate {y_live.mean():.2%})")

    if args.public:
        Xp, yp = load_rba(args.public, args.public_max_rows)
        if Xp.shape[0] > 0:
            X_list.append(Xp)
            y_list.append(yp)
            sources.append(f"rba:{Xp.shape[0]}")
            print(f"[train] rba: {Xp.shape[0]} samples (attack rate {yp.mean():.2%})")
        else:
            print(f"[train] rba file not found at {args.public}, skipping")

    if not X_list:
        print("[train] no data — provide --dataset with live samples and/or --public", file=sys.stderr)
        return 1

    X = np.concatenate(X_list, axis=0)
    y = np.concatenate(y_list, axis=0)
    print(f"[train] total: {X.shape[0]} samples, {X.shape[1]} features, attack rate {y.mean():.2%}")

    if len(np.unique(y)) < 2:
        print("[train] training set must contain both benign and attack samples", file=sys.stderr)
        return 1

    model = RandomForestRiskModel(
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
        random_state=args.seed,
    )
    metrics = model.train(X, y, sources=sources)

    print(f"[train] accuracy: {metrics['accuracy']:.4f}")
    print(f"[train] roc_auc : {metrics['roc_auc']:.4f}")
    print("[train] top features:")
    for name, imp in sorted(metrics["feature_importance"].items(), key=lambda kv: -kv[1])[:8]:
        print(f"         {name:30s} {imp:.4f}")

    os.makedirs(args.model_dir, exist_ok=True)
    model.save(args.model_dir)
    print(f"[train] saved → {args.model_dir}")
    with open(os.path.join(args.model_dir, "last_run.json"), "w") as f:
        json.dump({"sources": sources, "metrics": {
            "accuracy": metrics["accuracy"],
            "roc_auc": metrics["roc_auc"],
        }}, f, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
