"""Train matched XGBoost models for primary KEV-membership prediction.

The runnable implementation is delegated to ``train_risk_model_ablation`` at
the end of this compatibility module. Both models share one holdout, and the
target is catalog membership rather than all exploitation. Earlier helper code
in this module is retained for import compatibility but is not used by the CLI.
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
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

RANDOM_SEED = 42
TEST_SIZE = 0.20
METRIC_NAMES = ("precision", "recall", "f1", "roc_auc", "pr_auc")


def _score_metrics(y_true, y_pred, y_score):
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_score)),
        "pr_auc": float(average_precision_score(y_true, y_score)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }


def _add_features(frame, reference_time):
    features = pd.DataFrame(index=frame.index)
    for column in ("cvss_v3_score", "epss_score"):
        if column not in frame:
            features[column] = np.nan
        else:
            features[column] = pd.to_numeric(frame[column], errors="coerce")

    published = pd.to_datetime(frame.get("published_date"), errors="coerce", utc=True)
    if not isinstance(published, pd.Series):
        published = pd.Series(pd.NaT, index=frame.index, dtype="datetime64[ns, UTC]")
    features["days_since_published"] = (reference_time - published).dt.total_seconds() / 86400
    features["days_since_published"] = features["days_since_published"].clip(lower=0)

    description = frame.get("description", pd.Series("", index=frame.index)).fillna("").astype(str)
    features["description_length"] = description.str.len()
    features["cvss_epss_interaction"] = features["cvss_v3_score"] * features["epss_score"]
    features["cwe_id"] = frame.get("cwe_id", pd.Series("Unknown", index=frame.index)).fillna("Unknown").astype(str)
    return features


def _baseline_metrics(y_true, cvss, epss, random_seed):
    cvss = pd.to_numeric(cvss, errors="coerce")
    epss = pd.to_numeric(epss, errors="coerce")
    cvss_score = cvss.fillna(-1).to_numpy(dtype=float)
    epss_score = epss.fillna(-1).to_numpy(dtype=float)
    cvss_pred = cvss.ge(7.0).fillna(False).astype(int).to_numpy()
    epss_pred = epss.ge(0.5).fillna(False).astype(int).to_numpy()
    rng = np.random.default_rng(random_seed)
    random_score = rng.random(len(y_true))
    random_pred = np.zeros(len(y_true), dtype=int)
    positive_count = int(np.sum(y_true))
    if positive_count:
        random_pred[np.argpartition(random_score, -positive_count)[-positive_count:]] = 1
    return {
        "cvss_only_test": _score_metrics(y_true, cvss_pred, cvss_score),
        "epss_only_test": _score_metrics(y_true, epss_pred, epss_score),
        "random_base_rate_matched_test": _score_metrics(y_true, random_pred, random_score),
    }


def _format(value):
    return "n/a" if value is None else f"{value:.3f}"


def _write_report(path, model_metrics, test_baselines, stored_baselines, importances, best_params, label_counts):
    best_feature_lines = "\n".join(
        f"- `{name}`: importance {importance:.4f}"
        for name, importance in importances[:10]
    ) or "- No feature importances were available."
    comparisons = []
    for name, values in test_baselines.items():
        delta = model_metrics["f1"] - values["f1"]
        wording = "higher" if delta > 0 else "lower" if delta < 0 else "equal"
        comparisons.append(
            f"- Against **{name}**, test-set F1 is {abs(delta):.3f} {wording} "
            f"(model {model_metrics['f1']:.3f}; baseline {values['f1']:.3f})."
        )
    stored_rows = []
    for name, values in stored_baselines.items():
        stored_rows.append(
            f"| {name} (stored full-sample result) | "
            + " | ".join(_format(values.get(metric)) for metric in ("precision", "recall", "f1", "roc_auc"))
            + " |"
        )
    report = f"""# Risk model evaluation report

## Summary

The XGBoost classifier was evaluated on a stratified 20% holdout ({model_metrics['test_rows']:,} examples). It achieved precision **{model_metrics['precision']:.3f}**, recall **{model_metrics['recall']:.3f}**, F1 **{model_metrics['f1']:.3f}**, ROC-AUC **{model_metrics['roc_auc']:.3f}**, and PR-AUC **{model_metrics['pr_auc']:.3f}**. The positive fraction in the test set was {model_metrics['positive_rate']:.1%}.

## Comparison with simple baselines

The fairest comparison is the one below because all methods are scored on the same held-out rows:

{chr(10).join(comparisons)}

The `baseline_results.json` file contains earlier baseline scores computed over the full labeled sample, including records now assigned to the model's test split. These stored values are included for reference but are not an apples-to-apples comparison; use the same-test baseline figures above for conclusions.

| Stored baseline reference | Precision | Recall | F1 | ROC-AUC |
|---|---:|---:|---:|---:|
{chr(10).join(stored_rows)}

## What the model learned

Top encoded feature importances from the fitted model:

{best_feature_lines}

These importances describe which inputs the trees used to reproduce the labels in this sample. They are not causal effects and must not be read as evidence that these features predict verified real-world exploitation.

The label design creates a major limitation: positive examples are KEV entries or non-KEV CVEs with EPSS above 0.5, while negatives are non-KEV CVEs with EPSS at or below 0.05. EPSS is therefore part of the target definition, and the `label_type` column distinguishes KEV-backed `strong` positives from `weak_proxy` positives. The model can learn this labeling rule. Its score is not a substitute for validation against independently confirmed exploitation outcomes. Review proxy labels manually and evaluate on temporally separated, independently sourced outcomes before making claims about real-world prediction.

## Training setup

- Features: CVSS v3 score, EPSS score, CWE one-hot encoding, days since publication, description length, and a CVSS × EPSS interaction.
- Split: stratified 80/20 train/test with random seed {RANDOM_SEED}.
- Hyperparameters selected by 3-fold stratified grid search using average precision: `{json.dumps(best_params, sort_keys=True)}`.
- Label counts in the input: `{json.dumps(label_counts, sort_keys=True)}`.
"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report, encoding="utf-8")


def train_risk_model(input_path=None, baseline_path=None, model_path=None, results_dir=None):
    """Train, evaluate against test-set baselines, and write model artifacts."""
    project_root = Path(__file__).resolve().parents[1]
    input_path = Path(input_path or project_root / "data/processed/labeled_sample.parquet")
    baseline_path = Path(baseline_path or project_root / "results/baseline_results.json")
    model_path = Path(model_path or project_root / "models/artifacts/risk_model.joblib")
    results_dir = Path(results_dir or project_root / "results")
    if not input_path.is_file():
        raise FileNotFoundError(f"Labeled sample not found: {input_path}")
    if not baseline_path.is_file():
        raise FileNotFoundError(f"Baseline results not found: {baseline_path}. Run baseline_models.py first.")
    try:
        frame = pd.read_parquet(input_path)
        stored_baselines = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, ImportError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not load training inputs: {exc}") from exc

    required = {"actually_exploited", "cvss_v3_score", "epss_score"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"Labeled sample is missing required columns: {sorted(missing)}")
    y = pd.to_numeric(frame["actually_exploited"], errors="coerce")
    if y.isna().any() or not set(y.unique()).issubset({0, 1}) or y.nunique() != 2:
        raise ValueError("actually_exploited must contain both binary classes 0 and 1")
    y = y.astype(int)
    if y.value_counts().min() < 3:
        raise ValueError("At least three examples per class are required for stratified 3-fold tuning")

    test_ids = np.arange(len(frame))
    train_ids, test_ids = train_test_split(
        test_ids, test_size=TEST_SIZE, stratify=y, random_state=RANDOM_SEED
    )
    reference_time = pd.Timestamp(datetime.now(timezone.utc))
    X = _add_features(frame, reference_time)
    X_train, X_test = X.iloc[train_ids], X.iloc[test_ids]
    y_train, y_test = y.iloc[train_ids], y.iloc[test_ids]

    numeric_features = [
        "cvss_v3_score", "epss_score", "days_since_published",
        "description_length", "cvss_epss_interaction",
    ]
    preprocessor = ColumnTransformer(
        transformers=[
            ("numeric", SimpleImputer(strategy="median", add_indicator=True), numeric_features),
            ("cwe", OneHotEncoder(handle_unknown="ignore"), ["cwe_id"]),
        ],
        remainder="drop",
    )
    try:
        from xgboost import XGBClassifier
    except ImportError as exc:
        raise RuntimeError("XGBoost is required. Install dependencies with `pip install -r requirements.txt`.") from exc

    pipeline = Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", XGBClassifier(
            objective="binary:logistic", eval_metric="logloss", tree_method="hist",
            n_jobs=1, random_state=RANDOM_SEED,
        )),
    ])
    param_grid = {
        "classifier__n_estimators": [100, 200],
        "classifier__max_depth": [2, 3],
        "classifier__learning_rate": [0.05],
    }
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=RANDOM_SEED)
    search = GridSearchCV(
        pipeline, param_grid=param_grid, scoring="average_precision", cv=cv,
        n_jobs=1, refit=True, verbose=0,
    )
    search.fit(X_train, y_train)
    model = search.best_estimator_
    probabilities = model.predict_proba(X_test)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    model_metrics = _score_metrics(y_test, predictions, probabilities)
    model_metrics["test_rows"] = int(len(test_ids))
    model_metrics["positive_rate"] = float(y_test.mean())
    test_baselines = _baseline_metrics(
        y_test.to_numpy(), frame.iloc[test_ids]["cvss_v3_score"],
        frame.iloc[test_ids]["epss_score"], RANDOM_SEED,
    )

    stored_required = {"cvss_only", "epss_only", "random_base_rate_matched"}
    absent_stored = stored_required.difference(stored_baselines)
    if absent_stored:
        raise ValueError(f"Baseline JSON is missing entries: {sorted(absent_stored)}")
    importance_values = model.named_steps["classifier"].feature_importances_
    feature_names = model.named_steps["preprocessor"].get_feature_names_out()
    importances = sorted(
        [(str(name), float(value)) for name, value in zip(feature_names, importance_values)],
        key=lambda item: item[1], reverse=True,
    )

    comparison_rows = [{"model": "xgboost_test", **{m: model_metrics[m] for m in METRIC_NAMES}}]
    comparison_rows.extend(
        {"model": name, **{m: metrics[m] for m in METRIC_NAMES}}
        for name, metrics in test_baselines.items()
    )
    stored_names = {
        "cvss_only": "cvss_only_stored_full_sample",
        "epss_only": "epss_only_stored_full_sample",
        "random_base_rate_matched": "random_stored_full_sample",
    }
    for key, name in stored_names.items():
        comparison_rows.append({
            "model": name,
            **{metric: stored_baselines[key].get(metric) for metric in ("precision", "recall", "f1", "roc_auc")},
            "pr_auc": None,
        })

    results_dir.mkdir(parents=True, exist_ok=True)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)
    chart_path = results_dir / "feature_importance.png"
    top_features = importances[:20]
    plt.figure(figsize=(10, max(4, 0.38 * len(top_features))))
    if top_features:
        labels, values = zip(*reversed(top_features))
        plt.barh(labels, values, color="#4472C4")
    plt.title("XGBoost feature importance (gain)")
    plt.xlabel("Feature importance")
    plt.tight_layout()
    plt.savefig(chart_path, dpi=160)
    plt.close()

    evaluation = {
        "target": "actually_exploited",
        "test_size": TEST_SIZE,
        "random_seed": RANDOM_SEED,
        "test_rows": len(test_ids),
        "positive_rate": float(y_test.mean()),
        "model": "XGBoostClassifier",
        "best_params": search.best_params_,
        "best_cv_average_precision": float(search.best_score_),
        "model_metrics": model_metrics,
        "same_test_baselines": test_baselines,
        "stored_baselines_full_sample_reference": stored_baselines,
        "comparison_table": comparison_rows,
        "feature_importance": [{"feature": name, "importance": value} for name, value in importances],
        "label_type_counts": frame["label_type"].value_counts(dropna=False).to_dict() if "label_type" in frame else {},
        "caveat": "EPSS contributes to label construction; model performance is agreement with proxy labels, not independently verified real-world exploitation.",
    }
    report_path = results_dir / "risk_model_evaluation.json"
    report_path.write_text(json.dumps(evaluation, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    _write_report(
        results_dir / "risk_model_report.md", model_metrics, test_baselines,
        stored_baselines, importances, search.best_params_,
        frame["label_type"].value_counts(dropna=False).to_dict() if "label_type" in frame else {},
    )

    comparison = pd.DataFrame(comparison_rows).set_index("model")
    print("\nModel and baseline comparison (test-set methods are directly comparable):")
    print(comparison.to_string(float_format=lambda value: f"{value:.3f}"))
    print(f"\nSaved model: {model_path}")
    print(f"Saved feature chart: {chart_path}")
    print(f"Saved evaluation: {report_path}")
    print(f"Saved report: {results_dir / 'risk_model_report.md'}")
    return evaluation


try:
    from .train_risk_model_ablation import train_risk_models as train_risk_model
except ImportError:  # Direct `python models/train_risk_model.py` invocation.
    from train_risk_model_ablation import train_risk_models as train_risk_model


if __name__ == "__main__":
    try:
        train_risk_model()
    except (FileNotFoundError, ValueError, RuntimeError, ImportError, OSError) as exc:
        raise SystemExit(f"Risk model training failed: {exc}") from exc
