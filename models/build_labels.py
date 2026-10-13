"""Build separate KEV-membership and EPSS weak-proxy labeled cohorts.

KEV membership is the sole primary target (``in_kev``) and all rows in the
primary sample have ``label_type='strong'`` for that catalog-membership task.
Non-membership is not proof that a CVE was never exploited. EPSS-threshold
labels are saved in another file and must only be used for supplementary,
exploratory analysis; they never enter the primary metrics.
"""

from pathlib import Path

import pandas as pd

POSITIVE_EPSS_THRESHOLD = 0.5
NEGATIVE_EPSS_MAX = 0.05
SAMPLE_PER_CLASS = 300
MANUAL_REVIEW_SIZE = 50
RANDOM_SEED = 42


def build_labeled_sample(
    input_path=None,
    output_path=None,
    review_path=None,
    weak_proxy_path=None,
    sample_per_class=SAMPLE_PER_CLASS,
    review_size=MANUAL_REVIEW_SIZE,
    random_seed=RANDOM_SEED,
):
    """Build the balanced labeled sample and a reproducible manual-review CSV."""
    project_root = Path(__file__).resolve().parents[1]
    input_path = Path(input_path or project_root / "data/processed/vuln_dataset.parquet")
    output_path = Path(output_path or project_root / "data/processed/labeled_sample.parquet")
    review_path = Path(review_path or project_root / "data/processed/manual_review_sample.csv")
    weak_proxy_path = Path(weak_proxy_path or project_root / "data/processed/weak_proxy_sample.parquet")

    if not input_path.is_file():
        raise FileNotFoundError(f"Processed dataset not found: {input_path}")
    try:
        dataset = pd.read_parquet(input_path)
    except (OSError, ImportError, ValueError) as exc:
        raise RuntimeError(f"Could not read processed dataset {input_path}: {exc}") from exc

    required = {"cve_id", "epss_score", "in_kev"}
    missing = required.difference(dataset.columns)
    if missing:
        raise ValueError(f"Input dataset is missing required columns: {sorted(missing)}")
    if dataset["cve_id"].duplicated().any():
        raise ValueError("Input dataset contains duplicate CVE IDs; deduplicate before labeling.")
    if sample_per_class <= 0 or review_size < 0:
        raise ValueError("sample_per_class must be positive and review_size cannot be negative")

    dataset = dataset.copy()
    dataset["epss_score"] = pd.to_numeric(dataset["epss_score"], errors="coerce")
    in_kev = dataset["in_kev"].fillna(False).astype(bool)

    # Primary task: predict catalog membership from a balanced KEV/non-KEV sample.
    # A non-KEV control means "not listed in this snapshot", not "never exploited".
    strong_positive = dataset.loc[in_kev].copy()
    strong_positive["in_kev"] = 1
    strong_positive["label_type"] = "strong"
    strong_negative = dataset.loc[~in_kev].copy()
    strong_negative["in_kev"] = 0
    strong_negative["label_type"] = "strong"
    insufficient = []
    if len(strong_positive) < sample_per_class:
        insufficient.append(f"KEV-listed candidates: {len(strong_positive)} available, {sample_per_class} required")
    if len(strong_negative) < sample_per_class:
        insufficient.append(f"not-listed controls: {len(strong_negative)} available, {sample_per_class} required")
    if insufficient:
        raise ValueError("Not enough eligible CVEs to create the requested balanced sample (" + "; ".join(insufficient) + ").")

    positive_sample = strong_positive.sample(n=sample_per_class, random_state=random_seed)
    negative_sample = strong_negative.sample(n=sample_per_class, random_state=random_seed + 1)
    labeled = pd.concat([positive_sample, negative_sample], ignore_index=True)
    labeled = labeled.sample(frac=1, random_state=random_seed + 2).reset_index(drop=True)

    # Separate, explicitly exploratory proxy cohort. Never concatenate this into
    # the primary KEV membership sample or its reported evaluation.
    proxy_positive = dataset.loc[~in_kev & dataset["epss_score"].gt(POSITIVE_EPSS_THRESHOLD)].copy()
    proxy_negative = dataset.loc[~in_kev & dataset["epss_score"].le(NEGATIVE_EPSS_MAX)].copy()
    proxy_size = min(sample_per_class, len(proxy_positive), len(proxy_negative))
    proxy = pd.DataFrame()
    if proxy_size:
        proxy_positive["weak_proxy_label"] = 1
        proxy_positive["label_type"] = "weak_proxy"
        proxy_negative["weak_proxy_label"] = 0
        proxy_negative["label_type"] = "weak_proxy"
        proxy = pd.concat([
            proxy_positive.sample(n=proxy_size, random_state=random_seed + 4),
            proxy_negative.sample(n=proxy_size, random_state=random_seed + 5),
        ], ignore_index=True).sample(frac=1, random_state=random_seed + 6).reset_index(drop=True)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    review_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        labeled.to_parquet(output_path, index=False)
        if not proxy.empty:
            weak_proxy_path.parent.mkdir(parents=True, exist_ok=True)
            proxy.to_parquet(weak_proxy_path, index=False)
        labeled.sample(n=min(review_size, len(labeled)), random_state=random_seed + 3).to_csv(
            review_path, index=False
        )
    except (ImportError, OSError, ValueError) as exc:
        raise RuntimeError(f"Could not write labeled outputs: {exc}") from exc

    print(f"Saved {len(labeled)} examples to {output_path}")
    print(f"Primary KEV membership counts: {labeled['in_kev'].value_counts().sort_index().to_dict()}")
    print(f"Primary label provenance: {labeled['label_type'].value_counts().to_dict()}")
    if proxy.empty:
        print("Supplementary weak-proxy cohort not written: one or both EPSS-threshold classes had no examples.")
    else:
        print(f"Saved supplementary weak-proxy cohort ({len(proxy)} rows) to {weak_proxy_path}")
    print(f"Saved {min(review_size, len(labeled))} review rows to {review_path}")
    return labeled


if __name__ == "__main__":
    try:
        build_labeled_sample()
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"Label sample build failed: {exc}") from exc
