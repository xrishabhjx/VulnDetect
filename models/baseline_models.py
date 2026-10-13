"""Evaluate reference rules on primary KEV labels and separate proxy labels.

Primary metrics predict KEV catalog membership only. EPSS-threshold proxy
metrics are emitted under a separate supplementary key and are not primary.
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

CVSS_THRESHOLD = 7.0
EPSS_THRESHOLD = 0.5
RANDOM_SEED = 42


def _metrics(y_true, y_pred, y_score):
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_score)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }


def _evaluate_frame(frame, target, random_seed):
    required = {target, "cvss_v3_score", "epss_score"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"Labeled sample is missing required columns: {sorted(missing)}")
    if frame.empty:
        raise ValueError("Labeled sample is empty")
    y_true = pd.to_numeric(frame[target], errors="coerce")
    if y_true.isna().any() or not set(y_true.unique()).issubset({0, 1}) or y_true.nunique() != 2:
        raise ValueError(f"{target} must contain both binary classes 0 and 1")
    y_true = y_true.astype(int)
    cvss = pd.to_numeric(frame["cvss_v3_score"], errors="coerce")
    epss = pd.to_numeric(frame["epss_score"], errors="coerce")
    cvss_score, epss_score = cvss.fillna(-1).to_numpy(float), epss.fillna(-1).to_numpy(float)
    cvss_pred = cvss.ge(CVSS_THRESHOLD).fillna(False).astype(int).to_numpy()
    epss_pred = epss.ge(EPSS_THRESHOLD).fillna(False).astype(int).to_numpy()
    rng = np.random.default_rng(random_seed)
    random_scores = rng.random(len(y_true))
    positive_count = int(y_true.sum())
    random_pred = np.zeros(len(y_true), dtype=int)
    if positive_count:
        random_pred[np.argpartition(random_scores, -positive_count)[-positive_count:]] = 1
    return {
        "cvss_only": _metrics(y_true, cvss_pred, cvss_score),
        "epss_only": _metrics(y_true, epss_pred, epss_score),
        "random_base_rate_matched": _metrics(y_true, random_pred, random_scores),
    }


def evaluate_baselines(input_path=None, output_path=None, weak_proxy_path=None, random_seed=RANDOM_SEED):
    """Evaluate CVSS, EPSS, and prevalence-matched random predictions."""
    project_root = Path(__file__).resolve().parents[1]
    input_path = Path(input_path or project_root / "data/processed/labeled_sample.parquet")
    output_path = Path(output_path or project_root / "results/baseline_results.json")
    weak_proxy_path = Path(weak_proxy_path or project_root / "data/processed/weak_proxy_sample.parquet")
    if not input_path.is_file():
        raise FileNotFoundError(f"Labeled sample not found: {input_path}")
    try:
        frame = pd.read_parquet(input_path)
    except (OSError, ImportError, ValueError) as exc:
        raise RuntimeError(f"Could not read labeled sample {input_path}: {exc}") from exc

    if "in_kev" not in frame:
        raise ValueError("Primary labels require the in_kev KEV-membership target")
    results = {
        "primary_target": "in_kev",
        "primary_kev_membership": _evaluate_frame(frame, "in_kev", random_seed),
    }
    if weak_proxy_path.is_file():
        try:
            proxy = pd.read_parquet(weak_proxy_path)
        except (OSError, ImportError, ValueError) as exc:
            raise RuntimeError(f"Could not read supplementary weak-proxy sample: {exc}") from exc
        results["supplementary_weak_proxy"] = {
            "target": "weak_proxy_label",
            "metrics": _evaluate_frame(proxy, "weak_proxy_label", random_seed),
            "caveat": "Exploratory only: target is constructed from EPSS thresholds, so EPSS baseline agreement is tautological and this does not measure exploitation prediction.",
        }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        output_path.write_text(json.dumps(results, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"Could not write baseline results to {output_path}: {exc}") from exc

    for cohort, methods in results.items():
        if cohort == "primary_target" or not isinstance(methods, dict):
            continue
        label = "in_kev" if cohort == "primary_kev_membership" else "weak_proxy_label"
        if cohort == "supplementary_weak_proxy":
            methods = methods.get("metrics", {})
        print(f"\n{cohort} ({label})")
        for name, metrics in methods.items():
            if not isinstance(metrics, dict) or "f1" not in metrics:
                continue
            print(f"{name}: precision={metrics['precision']:.4f} recall={metrics['recall']:.4f} f1={metrics['f1']:.4f} ROC-AUC={metrics['roc_auc']:.4f}")
            print("  confusion_matrix [[TN, FP], [FN, TP]]:")
            print(np.asarray(metrics["confusion_matrix"]))
    print(f"\nSaved results to {output_path}")
    return results


if __name__ == "__main__":
    try:
        evaluate_baselines()
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"Baseline evaluation failed: {exc}") from exc
