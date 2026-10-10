"""Train the Random Forest + Isolation Forest bundle (run in Google Colab or locally).

    python -m ml.train                                   # synthetic + data/dataset.csv if present
    python -m ml.train --data data/dataset.csv --synthetic 0   # real recordings only
    python -m ml.train --data a.csv --data b.csv --real-weight 3

Writes ``models/model.pkl`` (loaded by the collector) and ``models/metrics.json``
(accuracy, false-positive rate, per-scenario detection, latency benchmark).
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.model_selection import train_test_split

from common.config import SETTINGS
from common.features import FEATURE_COLUMNS
from common.model import ThreatModel
from ml.generate_dataset import generate


def load_data(paths: list[str], synthetic_rows: int, seed: int) -> pd.DataFrame:
    frames = []
    for p in paths:
        if Path(p).exists():
            df = pd.read_csv(p)
            missing = set(FEATURE_COLUMNS + ["label"]) - set(df.columns)
            if missing:
                raise SystemExit(f"{p} is missing columns {sorted(missing)}")
            if "source" not in df:
                df["source"] = "real"
            fallback = df["label"].map({0: "real_normal", 1: "real_attack"})
            df["scenario"] = df["scenario"].fillna(fallback) if "scenario" in df else fallback
            frames.append(df)
            print(f"loaded {len(df):>7} rows from {p}  (suspicious={int(df['label'].sum())})")
        else:
            print(f"skip   {p} (not found)")
    if synthetic_rows > 0:
        header, rows = generate(synthetic_rows, seed=seed)
        frames.append(pd.DataFrame(rows, columns=header))
        print(f"generated {synthetic_rows} synthetic rows")
    if not frames:
        raise SystemExit("no training data - record with `python -m sensors.collector --record` "
                         "or allow --synthetic rows")
    df = pd.concat(frames, ignore_index=True)
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    df = df.dropna(subset=FEATURE_COLUMNS + ["label"])
    df[FEATURE_COLUMNS] = df[FEATURE_COLUMNS].clip(lower=0)
    df["label"] = df["label"].astype(int)
    return df


def evaluate(model: ThreatModel, X: np.ndarray, y: np.ndarray, threshold: float) -> dict:
    s = model.score(X)
    pred = (s >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {"n": int(len(y)), "accuracy": accuracy_score(y, pred),
           "precision": precision_score(y, pred, zero_division=0),
           "recall": recall_score(y, pred, zero_division=0),
           "f1": f1_score(y, pred, zero_division=0),
           "false_positive_rate": fp / max(fp + tn, 1),
           "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}}
    if len(set(y)) == 2:
        out["roc_auc"] = roc_auc_score(y, s)
    return {k: (round(float(v), 4) if isinstance(v, float) else v) for k, v in out.items()}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", action="append", default=None,
                    help="CSV(s) recorded by the collector (default data/dataset.csv)")
    ap.add_argument("--synthetic", type=int, default=30000, help="synthetic rows to add")
    ap.add_argument("--real-weight", type=float, default=3.0,
                    help="sample weight of real rows relative to synthetic ones")
    ap.add_argument("--trees", type=int, default=200)
    ap.add_argument("--max-depth", type=int, default=18)
    ap.add_argument("--threshold", type=float, default=SETTINGS.alert_threshold)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default=str(SETTINGS.model_path))
    a = ap.parse_args(argv)

    df = load_data(a.data or [str(SETTINGS.dataset_path)], a.synthetic, a.seed)
    print(f"total {len(df)} rows, suspicious {df['label'].mean():.1%}")
    if df["label"].nunique() < 2:
        raise SystemExit("need both normal (0) and suspicious (1) rows - add --synthetic rows "
                         "or record an attack simulation")

    strat = df["label"].astype(str) + "_" + df["source"].astype(str)
    tr, te = train_test_split(df, test_size=0.2, random_state=a.seed, stratify=strat)
    Xtr, ytr = tr[FEATURE_COLUMNS].to_numpy(np.float64), tr["label"].to_numpy()
    w = np.where(tr["source"].eq("synthetic"), 1.0, a.real_weight)

    t0 = time.perf_counter()
    rf = RandomForestClassifier(n_estimators=a.trees, max_depth=a.max_depth, min_samples_leaf=2,
                                max_features="sqrt", class_weight="balanced_subsample",
                                n_jobs=-1, random_state=a.seed)
    rf.fit(Xtr, ytr, sample_weight=w)
    normal = Xtr[ytr == 0]
    iforest = IsolationForest(n_estimators=150, max_samples=min(4096, len(normal)),
                              contamination="auto", n_jobs=-1, random_state=a.seed).fit(normal)
    raw = -iforest.score_samples(normal)
    if_range = (float(np.percentile(raw, 50)), float(np.percentile(raw, 99.5)))
    print(f"trained in {time.perf_counter() - t0:.1f}s")

    bundle = {"rf": rf, "iforest": iforest, "if_range": if_range,
              "features": FEATURE_COLUMNS, "threshold": a.threshold,
              "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
              "sklearn_version": sklearn.__version__}
    model = ThreatModel(bundle)

    Xte, yte = te[FEATURE_COLUMNS].to_numpy(np.float64), te["label"].to_numpy()
    metrics = {"overall": evaluate(model, Xte, yte, a.threshold)}
    real = te["source"].ne("synthetic").to_numpy()
    if real.any():
        metrics["real_only"] = evaluate(model, Xte[real], yte[real], a.threshold)
    scores = model.score(Xte)
    metrics["per_scenario"] = {
        scen: {"n": int(m.sum()), "label": int(yte[m][0]),
               "flagged_rate": round(float((scores[m] >= a.threshold).mean()), 4)}
        for scen in sorted(te["scenario"].unique()) if (m := te["scenario"].eq(scen).to_numpy()).any()}
    metrics["feature_importance"] = dict(sorted(
        ((c, round(float(v), 4)) for c, v in zip(FEATURE_COLUMNS, rf.feature_importances_)),
        key=lambda kv: -kv[1]))

    batch = Xte[:300]
    model.score(batch)
    t0 = time.perf_counter()
    for _ in range(20):
        model.score(batch)
    metrics["inference_ms_per_300_rows"] = round((time.perf_counter() - t0) / 20 * 1000, 2)
    metrics["threshold"] = a.threshold
    metrics["rows"] = {"train": int(len(tr)), "test": int(len(te)),
                       "real": int(df["source"].ne("synthetic").sum())}

    bundle["metrics"] = {"accuracy": metrics["overall"]["accuracy"],
                         "fpr": metrics["overall"]["false_positive_rate"],
                         "recall": metrics["overall"]["recall"]}
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    import joblib
    joblib.dump(bundle, out, compress=3)
    (out.parent / "metrics.json").write_text(json.dumps(metrics, indent=2))

    o = metrics["overall"]
    print(f"\naccuracy {o['accuracy']:.2%}  precision {o['precision']:.2%}  recall {o['recall']:.2%}  "
          f"FPR {o['false_positive_rate']:.2%}  AUC {o.get('roc_auc', float('nan')):.4f}")
    if "real_only" in metrics:
        r = metrics["real_only"]
        print(f"real-only: accuracy {r['accuracy']:.2%}  recall {r['recall']:.2%}  "
              f"FPR {r['false_positive_rate']:.2%}  (n={r['n']})")
    print("per scenario (fraction flagged):")
    for k, v in metrics["per_scenario"].items():
        print(f"  {'ATTACK' if v['label'] else 'normal'}  {k:<16} {v['flagged_rate']:.1%}  (n={v['n']})")
    print(f"inference: {metrics['inference_ms_per_300_rows']} ms per 300-process batch")
    print(f"saved {out} ({out.stat().st_size / 1e6:.1f} MB) and {out.parent / 'metrics.json'}")


if __name__ == "__main__":
    main()
