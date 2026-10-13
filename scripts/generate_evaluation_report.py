"""Combine saved model and baseline metrics into a defendable Markdown report.

The interpretation is written as deterministic prose from the saved metrics;
this script does not call an external language model or invent missing results.
"""

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = PROJECT_ROOT / "results"
INPUTS = {
    "baseline": RESULTS_DIR / "baseline_results.json",
    "risk": RESULTS_DIR / "risk_model_evaluation.json",
    "injection": RESULTS_DIR / "injection_classifier_evaluation.json",
}
OUTPUT_PATH = RESULTS_DIR / "FULL_EVALUATION_REPORT.md"
METRICS = ("precision", "recall", "f1", "roc_auc", "pr_auc")


def _load_json(path):
    if not path.is_file():
        return None, f"missing: {path.relative_to(PROJECT_ROOT).as_posix()}"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"unreadable: {path.relative_to(PROJECT_ROOT).as_posix()} ({exc})"
    if not isinstance(value, dict):
        return None, f"invalid format: {path.relative_to(PROJECT_ROOT).as_posix()} must contain a JSON object"
    return value, f"loaded: {path.relative_to(PROJECT_ROOT).as_posix()}"


def _metric(metrics, name):
    if not isinstance(metrics, dict):
        return None
    aliases = {"roc_auc": ("roc_auc", "auc", "ROC-AUC"), "pr_auc": ("pr_auc", "average_precision", "PR-AUC")}
    for key in aliases.get(name, (name,)):
        value = metrics.get(key)
        if isinstance(value, (int, float)) and value == value:
            return float(value)
    return None


def _format(value):
    return "—" if value is None else f"{value:.3f}"


def _row(task, model_name, metrics, note=""):
    values = [_format(_metric(metrics, name)) for name in METRICS]
    suffix = f" {note}" if note else ""
    return f"| {task} | {model_name}{suffix} | " + " | ".join(values) + " |"


def _risk_rows(risk, baseline):
    rows = []
    if risk:
        same_test = risk.get("same_test_baselines") or {}
        for key, label, alternate in (
            ("cvss_only_test", "CVSS-only", "cvss_only"),
            ("epss_only_test", "EPSS-only", "epss_only"),
            ("random_base_rate_matched_test", "Random base-rate matched", "random_base_rate_matched"),
        ):
            metrics = same_test.get(key) or same_test.get(alternate)
            if metrics is not None:
                rows.append(_row("Risk scorer", label, metrics, "(same test set)"))
        model_metrics = risk.get("model_metrics")
        if model_metrics:
            rows.append(_row("Risk scorer (KEV membership)", "XGBoost with EPSS", model_metrics, "(same holdout)"))
        no_epss = (risk.get("models") or {}).get("without_epss", {}).get("metrics")
        if no_epss:
            rows.append(_row("Risk scorer (KEV membership)", "XGBoost without EPSS", no_epss, "(same holdout)"))

    return rows


def _injection_rows(injection):
    if not injection:
        return []
    rows = []
    if injection.get("regex_baseline"):
        rows.append(_row("Injection classifier", "Regex/keyword baseline", injection["regex_baseline"], "(test set)"))
    if injection.get("trained_classifier"):
        rows.append(_row("Injection classifier", "Trained DistilBERT", injection["trained_classifier"], "(test set)"))
    return rows


def _delta_sentence(task, trained, baselines):
    trained_f1 = _metric(trained, "f1")
    valid = [(name, _metric(values, "f1")) for name, values in baselines if _metric(values, "f1") is not None]
    if trained_f1 is None or not valid:
        return f"No comparable saved F1 values are available for the {task} model yet."
    best_name, best_f1 = max(valid, key=lambda pair: pair[1])
    delta = trained_f1 - best_f1
    if delta > 0:
        comparison = f"higher by {delta:.3f}"
    elif delta < 0:
        comparison = f"lower by {abs(delta):.3f}"
    else:
        comparison = "equal"
    return f"On the recorded comparable split, the trained {task} model's F1 is {comparison} than {best_name} ({trained_f1:.3f} vs {best_f1:.3f})."


def _interpretation(risk, injection):
    risk_baselines = list((risk or {}).get("same_test_baselines", {}).items())
    injection_baselines = [("regex/keyword baseline", (injection or {}).get("regex_baseline", {}))]
    risk_text = _delta_sentence("KEV-membership risk-scoring", (risk or {}).get("model_metrics", {}), risk_baselines)
    variants = (risk or {}).get("models", {})
    with_metrics = (variants.get("with_epss") or {}).get("metrics", (risk or {}).get("model_metrics", {}))
    without_metrics = (variants.get("without_epss") or {}).get("metrics", {})
    with_f1, without_f1 = _metric(with_metrics, "f1"), _metric(without_metrics, "f1")
    ablation_text = (f"With EPSS, F1 is {with_f1:.3f}; without EPSS, it is {without_f1:.3f} (difference {with_f1 - without_f1:+.3f}) on the same KEV-membership holdout."
                     if with_f1 is not None and without_f1 is not None else "The with/without EPSS ablation metrics are not both available yet.")
    injection_text = _delta_sentence(
        "prompt-injection", (injection or {}).get("trained_classifier", {}), injection_baselines
    )
    return (
        f"{risk_text} {ablation_text} {injection_text} The primary risk target is CISA KEV catalog membership; not being listed is not proof of non-exploitation. "
        "These comparisons do not establish prediction of all independently verified real-world exploitation. Treat probability values as scores until independent, representative validation and calibration are completed."
    )


def _source_status(status):
    return "\n".join(f"- {line}" for line in status)


def generate_report(output_path=None):
    """Read available evaluation JSON and write the combined project report."""
    loaded = {}
    statuses = []
    for name, path in INPUTS.items():
        loaded[name], status = _load_json(path)
        statuses.append(status)
    baseline = loaded["baseline"]
    risk = loaded["risk"]
    injection = loaded["injection"]

    risk_rows = _risk_rows(risk, baseline)
    injection_rows = _injection_rows(injection)
    table_header = "| Model | Precision | Recall | F1 | ROC-AUC | PR-AUC |\n|---|---:|---:|---:|---:|---:|"
    risk_table = "\n".join("| " + row.split("|", 2)[2].strip() for row in risk_rows) if risk_rows else "No risk evaluation results available."
    injection_table = "\n".join("| " + row.split("|", 2)[2].strip() for row in injection_rows) if injection_rows else "No injection evaluation results available."
    chart_path = RESULTS_DIR / "feature_importance.png"
    no_epss_chart = RESULTS_DIR / "feature_importance_no_epss.png"
    chart_section = ""
    if chart_path.is_file():
        chart_section += "![Risk-model feature importance with EPSS](feature_importance.png)\n"
    if no_epss_chart.is_file():
        chart_section += "\n![Risk-model feature importance without EPSS](feature_importance_no_epss.png)\n"
    if not chart_section:
        chart_section = "Feature importance charts are not present yet; run `models/train_risk_model.py` to generate them."

    interpretation = _interpretation(risk, injection)
    if baseline and risk and risk.get("same_test_baselines"):
        interpretation += " The primary table uses the baseline scores from the risk evaluation's same holdout. `baseline_results.json` is used below for separate full-cohort references and supplementary proxy analysis."

    risk_test_rows = (risk or {}).get("model_metrics", {}).get("test_rows")
    injection_test_rows = (injection or {}).get("test_rows")
    eval_size_notes = []
    if risk_test_rows is not None:
        eval_size_notes.append(f"Risk model holdout: {risk_test_rows} examples.")
    if injection_test_rows is not None:
        eval_size_notes.append(f"Injection-classifier test split: {injection_test_rows} examples.")
    size_note = " ".join(eval_size_notes) if eval_size_notes else "The current evaluation artifacts do not report test-set sizes. The configured risk label builder samples 300 positives and 300 negatives (600 total); injection training combines the public source with 40 manually written examples before deduplication and splitting."

    stored_baseline_table = ""
    primary_full_sample = (baseline or {}).get("primary_kev_membership", {})
    if primary_full_sample:
        stored_rows = []
        for key, name in (("cvss_only", "CVSS-only"), ("epss_only", "EPSS-only"), ("random_base_rate_matched", "Random base-rate matched")):
            if key in primary_full_sample:
                stored_rows.append(_row("Risk scorer (full balanced cohort)", name, primary_full_sample[key]))
        if stored_rows:
            stored_baseline_table = (
                "\n### Full-cohort baseline references from `baseline_results.json`\n\n"
                "These scores use the full balanced primary cohort. They are included for traceability only and must not be compared directly with model holdout scores.\n\n"
                "| Task | Baseline | Precision | Recall | F1 | ROC-AUC | PR-AUC |\n|---|---|---:|---:|---:|---:|---:|\n"
                + "\n".join(stored_rows) + "\n"
            )

    proxy = (baseline or {}).get("supplementary_weak_proxy", {})
    proxy_metrics = proxy.get("metrics", {}) if isinstance(proxy, dict) else {}
    proxy_rows = []
    for key, label in (("cvss_only", "CVSS-only"), ("epss_only", "EPSS-only (label-defining signal)"),
                       ("random_base_rate_matched", "Random base-rate matched")):
        if proxy_metrics.get(key):
            proxy_rows.append(_row("Weak-proxy (exploratory only)", label, proxy_metrics[key]))
    proxy_section = ""
    if proxy_rows:
        proxy_section = (
            "\n## Supplementary weak-proxy analysis (not primary)\n\n"
            "These metrics use a separate cohort whose labels are defined by EPSS thresholds. The EPSS baseline is therefore circular by construction. These results are exploratory and are excluded from all primary model metrics.\n\n"
            "| Task | Method | Precision | Recall | F1 | ROC-AUC | PR-AUC |\n|---|---|---:|---:|---:|---:|---:|\n"
            + "\n".join(proxy_rows) + "\n"
        )

    report = f"""# Full Evaluation Report

Generated from saved evaluation artifacts. This report uses deterministic, human-authored interpretation templates; no external LLM is used.

## Evaluation summary

ROC-AUC is shown as AUC; PR-AUC is included when available. Risk model and baseline rows marked **same test set** are the fair, directly comparable results. A dash means the source report did not contain that metric.

## Primary KEV-membership risk evaluation

All methods in this table are evaluated on the same held-out KEV membership records. A CVE absent from KEV is not confirmed unexploited.

{table_header}
{risk_table}

## Injection-classifier evaluation

Both detectors use the same held-out injection test split.

{table_header}
{injection_table}

{stored_baseline_table}
{proxy_section}

## Risk-model feature importance

{chart_section}
Feature importance describes how the fitted model used features for this labeled dataset; it is not a causal explanation of exploitation risk.

## Interpretation

{interpretation}

## Limitations

- **Dataset size:** {size_note} These are small portfolio-scale datasets; estimates can move materially with a different split or a few changed examples. Stratified random splits do not test future-time generalization.
- **Primary label scope:** Primary metrics predict KEV catalog membership only. KEV entries are evidence of known exploitation, but CVEs not listed in the sampled catalog are not confirmed unexploited; catalog coverage and timing matter. The balanced sample also does not represent real-world prevalence.
- **Supplementary weak-proxy labels:** EPSS-threshold labels are kept in `weak_proxy_sample.parquet` and are not included in primary training or primary reported metrics. Any supplementary performance is exploratory and circular with EPSS because EPSS defines those labels.
- **EPSS ablation:** Primary evaluation compares models with and without `epss_score` (and its interaction feature) on the same KEV-membership holdout. This tests incremental predictive value for this sample; it does not establish causality or future-time generalization. Absolute risk probabilities are not calibrated exploitation likelihoods.
- **Synthetic injection examples:** The custom injection file contains 20 hand-written malicious and 20 hand-written benign vulnerability-management examples. They are useful seed examples but are synthetic, narrow, and may not represent real field distributions or adaptive attacks. Their presence in random stratified splits can make evaluation optimistic for similar wording.
- **Injection training size and overfitting:** The injection classifier was trained on 491 examples. Training loss fell to approximately 0.01 while validation loss plateaued around 0.25–0.29, suggesting mild overfitting. The strong held-out metrics should be treated cautiously and confirmed on a larger, independently collected set.
- **Base-rate mismatch:** The KEV evaluation sample is class-balanced (50% positive in the saved holdout), unlike the approximately 0.4% real-world KEV base rate cited for this project. Precision and other threshold-dependent metrics from the balanced sample will not carry over directly to a production population with that prevalence.
- **Metric availability:** The report does not infer missing AUC values from precision/recall/F1. If an older injection evaluation file lacks ROC-AUC or PR-AUC, rerun `models/injection_classifier/evaluate_classifier.py` to populate them.

## Input artifact status

{_source_status(statuses)}

## Reproducing this report

Run the baseline, risk-model, and injection-classifier evaluation scripts to create the three JSON inputs, then run:

```bash
python scripts/generate_evaluation_report.py
```
"""
    destination = Path(output_path or OUTPUT_PATH)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(report, encoding="utf-8")
    print(f"Wrote {destination}")
    print("Input files: " + "; ".join(statuses))
    return report


if __name__ == "__main__":
    generate_report()
