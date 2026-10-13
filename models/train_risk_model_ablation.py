"""Train matched XGBoost classifiers predicting KEV catalog membership.

The EPSS ablation is the central comparison: both versions use the same rows,
split, target, and tuning procedure. EPSS-threshold proxy labels are not used.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

SEED = 42
METRICS = ("precision", "recall", "f1", "roc_auc", "pr_auc")


def _metrics(y, pred, score):
    return {"precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "f1": float(f1_score(y, pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y, score)),
            "pr_auc": float(average_precision_score(y, score)),
            "confusion_matrix": confusion_matrix(y, pred, labels=[0, 1]).tolist()}


def _features(frame, now, use_epss):
    x = pd.DataFrame(index=frame.index)
    x["cvss_v3_score"] = pd.to_numeric(frame["cvss_v3_score"], errors="coerce")
    if use_epss:
        x["epss_score"] = pd.to_numeric(frame["epss_score"], errors="coerce")
    published = pd.to_datetime(frame.get("published_date"), errors="coerce", utc=True)
    x["days_since_published"] = ((now - published).dt.total_seconds() / 86400).clip(lower=0)
    x["description_length"] = frame.get("description", pd.Series("", index=frame.index)).fillna("").astype(str).str.len()
    if use_epss:
        x["cvss_epss_interaction"] = x["cvss_v3_score"] * x["epss_score"]
    x["cwe_id"] = frame.get("cwe_id", pd.Series("Unknown", index=frame.index)).fillna("Unknown").astype(str)
    return x


def _baseline(y, frame):
    cvss, epss = pd.to_numeric(frame.cvss_v3_score, errors="coerce"), pd.to_numeric(frame.epss_score, errors="coerce")
    scores = {"cvss_only": cvss.fillna(-1).to_numpy(float), "epss_only": epss.fillna(-1).to_numpy(float)}
    predictions = {"cvss_only": cvss.ge(7).fillna(False).astype(int).to_numpy(),
                   "epss_only": epss.ge(.5).fillna(False).astype(int).to_numpy()}
    rng = np.random.default_rng(SEED); scores["random_base_rate_matched"] = rng.random(len(y))
    predictions["random_base_rate_matched"] = np.zeros(len(y), dtype=int)
    n = int(np.sum(y))
    if n: predictions["random_base_rate_matched"][np.argpartition(scores["random_base_rate_matched"], -n)[-n:]] = 1
    return {k: _metrics(y, predictions[k], scores[k]) for k in scores}


def _fit(frame, y, train_ids, test_ids, now, use_epss):
    from xgboost import XGBClassifier
    x = _features(frame, now, use_epss)
    numeric = ["cvss_v3_score", "days_since_published", "description_length"]
    if use_epss: numeric += ["epss_score", "cvss_epss_interaction"]
    prep = ColumnTransformer([("numeric", SimpleImputer(strategy="median", add_indicator=True), numeric),
                              ("cwe", OneHotEncoder(handle_unknown="ignore"), ["cwe_id"])])
    pipe = Pipeline([("preprocessor", prep), ("classifier", XGBClassifier(objective="binary:logistic", eval_metric="logloss", tree_method="hist", n_jobs=1, random_state=SEED))])
    search = GridSearchCV(pipe, {"classifier__n_estimators": [100, 200], "classifier__max_depth": [2, 3], "classifier__learning_rate": [.05]},
        scoring="average_precision", cv=StratifiedKFold(3, shuffle=True, random_state=SEED), n_jobs=1, refit=True)
    search.fit(x.iloc[train_ids], y.iloc[train_ids])
    model = search.best_estimator_; model.vulnintel_include_epss = use_epss
    p = model.predict_proba(x.iloc[test_ids])[:, 1]
    metrics = _metrics(y.iloc[test_ids], (p >= .5).astype(int), p)
    metrics.update(test_rows=len(test_ids), positive_rate=float(y.iloc[test_ids].mean()))
    names = model.named_steps["preprocessor"].get_feature_names_out()
    vals = model.named_steps["classifier"].feature_importances_
    importance = sorted(((str(n), float(v)) for n, v in zip(names, vals)), key=lambda a: a[1], reverse=True)
    return model, search, metrics, importance


def train_risk_models(input_path=None, results_dir=None, with_epss_path=None, without_epss_path=None):
    root = Path(__file__).resolve().parents[1]
    data = Path(input_path or root / "data/processed/labeled_sample.parquet")
    out = Path(results_dir or root / "results")
    with_path = Path(with_epss_path or root / "models/artifacts/risk_model.joblib")
    without_path = Path(without_epss_path or root / "models/artifacts/risk_model_no_epss.joblib")
    if not data.exists(): raise FileNotFoundError(f"Primary KEV labeled sample missing: {data}")
    frame = pd.read_parquet(data)
    if "in_kev" not in frame: raise ValueError("Expected primary target in_kev; rerun models/build_labels.py")
    y = pd.to_numeric(frame.in_kev, errors="coerce")
    if y.isna().any() or y.nunique() != 2 or not set(y.unique()).issubset({0, 1}): raise ValueError("in_kev must contain binary classes 0 and 1")
    y = y.astype(int)
    train_ids, test_ids = train_test_split(np.arange(len(frame)), test_size=.2, stratify=y, random_state=SEED)
    now = pd.Timestamp(datetime.now(timezone.utc))
    variants = {}
    for key, use_epss, path in (("with_epss", True, with_path), ("without_epss", False, without_path)):
        model, search, metrics, importance = _fit(frame, y, train_ids, test_ids, now, use_epss)
        path.parent.mkdir(parents=True, exist_ok=True); joblib.dump(model, path)
        variants[key] = {"metrics": metrics, "best_params": search.best_params_, "cv_average_precision": float(search.best_score_),
                         "model_path": path.relative_to(root).as_posix(), "importance": importance}
        top = importance[:20]; chart = out / ("feature_importance.png" if use_epss else "feature_importance_no_epss.png")
        out.mkdir(parents=True, exist_ok=True); plt.figure(figsize=(10, max(4, .38 * len(top))))
        if top:
            labels, values = zip(*reversed(top)); plt.barh(labels, values)
        plt.title(f"KEV-membership feature importance ({key})"); plt.tight_layout(); plt.savefig(chart, dpi=160); plt.close()
    baselines = _baseline(y.iloc[test_ids].to_numpy(), frame.iloc[test_ids])
    comparison = [{"model": k, **{m: v["metrics"][m] for m in METRICS}} for k, v in variants.items()]
    comparison.extend({"model": k, **{m: v[m] for m in METRICS}} for k, v in baselines.items())
    report_data = {"target": "in_kev", "target_interpretation": "KEV membership; non-membership is not confirmed non-exploitation.",
        "test_size": .2, "random_seed": SEED, "test_rows": len(test_ids), "positive_rate": float(y.iloc[test_ids].mean()),
        "model_metrics": variants["with_epss"]["metrics"], "models": variants,
        "same_test_baselines": baselines, "comparison_table": comparison,
        "label_type_counts": frame.get("label_type", pd.Series(dtype=str)).value_counts().to_dict(),
        "supplementary_weak_proxy": {"status": "separate from primary metrics", "dataset": "data/processed/weak_proxy_sample.parquet",
            "note": "EPSS-threshold constructed labels are exploratory only and not used here."},
        "caveat": "Metrics predict KEV catalog membership only; they do not establish calibrated or complete real-world exploitation prediction."}
    out.mkdir(parents=True, exist_ok=True)
    (out / "risk_model_evaluation.json").write_text(json.dumps(report_data, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    lines = ["# Risk model evaluation report", "", "## Primary task: KEV catalog membership", "",
        "A negative means the CVE is not listed in the sampled KEV catalog snapshot; it does not mean confirmed unexploited. Both variants use identical train/test CVEs and tuning.", "",
        "| Model | Precision | Recall | F1 | ROC-AUC | PR-AUC |", "|---|---:|---:|---:|---:|---:|"]
    lines += ["| " + row["model"] + " | " + " | ".join(f"{row[m]:.3f}" for m in METRICS) + " |" for row in comparison]
    lines += ["", "## EPSS ablation", "", "Compare `with_epss` to `without_epss`: the latter excludes both epss_score and cvss_epss_interaction. A difference on this shared holdout is evidence about incremental performance beyond EPSS for predicting KEV membership, not a causal result or proof of future generalization.", "",
        "## Supplementary weak-proxy labels", "", "EPSS-threshold labels are stored separately in `data/processed/weak_proxy_sample.parquet` and excluded from primary model training and metrics. Any analysis on them is exploratory and circular with EPSS.", "",
        "## Feature importance and limitations", "", "Charts: `feature_importance.png` (with EPSS) and `feature_importance_no_epss.png` (without EPSS). Importances represent model reliance, not causal effects. Balanced sampling changes prevalence; the probabilities are not calibrated real-world exploitation likelihoods."]
    (out / "risk_model_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(pd.DataFrame(comparison).set_index("model").to_string(float_format=lambda v: f"{v:.3f}"))
    print(f"Wrote {out / 'risk_model_evaluation.json'}")
    return report_data


if __name__ == "__main__":
    try: train_risk_models()
    except (OSError, ValueError, RuntimeError, ImportError) as exc: raise SystemExit(f"Risk model training failed: {exc}") from exc
