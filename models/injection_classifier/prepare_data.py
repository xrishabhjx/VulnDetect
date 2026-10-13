"""Download, normalize, deduplicate, and split prompt-injection examples."""

from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

DATASET_ID = "deepset/prompt-injections"
RANDOM_SEED = 42
TEXT_COLUMNS = ("text", "prompt", "sentence", "input", "content")
LABEL_COLUMNS = ("label", "labels", "is_injection", "target")


def _normalize_label(value, class_names=None):
    """Return 1 for injection and 0 for benign, using HF class names if supplied."""
    if class_names is not None and not pd.isna(value):
        try:
            value = class_names[int(value)]
        except (IndexError, TypeError, ValueError):
            pass
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)) and value in (0, 1):
        # The deepset dataset convention is 1=injection, 0=benign.
        return int(value)
    normalized = str(value).strip().lower()
    if normalized in {"1", "injection", "malicious", "positive", "attack", "true"}:
        return 1
    if normalized in {"0", "benign", "normal", "negative", "safe", "false"}:
        return 0
    raise ValueError(f"Unrecognized prompt-injection label: {value!r}")


def _dataset_to_frame(dataset_dict):
    frames = []
    for split_name, dataset in dataset_dict.items():
        rows = dataset.to_list()
        if not rows:
            continue
        available = rows[0].keys()
        text_column = next((name for name in TEXT_COLUMNS if name in available), None)
        label_column = next((name for name in LABEL_COLUMNS if name in available), None)
        if text_column is None or label_column is None:
            raise ValueError(
                f"Unexpected Hugging Face schema in split {split_name!r}; "
                f"expected a text and label column, found {sorted(available)}"
            )
        label_feature = dataset.features.get(label_column)
        class_names = getattr(label_feature, "names", None)
        records = []
        for row in rows:
            text = row.get(text_column)
            if not isinstance(text, str) or not text.strip():
                continue
            records.append({
                "text": text.strip(),
                "label": _normalize_label(row.get(label_column), class_names),
                "category": "unspecified",
                "context": "prompt-injection dataset",
                "source": f"huggingface:{DATASET_ID}:{split_name}",
            })
        frames.append(pd.DataFrame.from_records(records))
    if not frames:
        raise ValueError(f"Hugging Face dataset {DATASET_ID} contained no usable examples")
    return pd.concat(frames, ignore_index=True)


def prepare_data(custom_csv=None, output_dir=None, random_seed=RANDOM_SEED):
    """Combine HF and custom examples, then write stratified 70/15/15 CSV splits."""
    project_root = Path(__file__).resolve().parents[2]
    custom_csv = Path(custom_csv or project_root / "data/raw/custom_injection_examples.csv")
    output_dir = Path(output_dir or project_root / "data/processed")
    if not custom_csv.is_file():
        raise FileNotFoundError(f"Supplementary examples CSV not found: {custom_csv}")

    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise RuntimeError("Install Hugging Face datasets with `pip install -r requirements.txt`.") from exc
    try:
        hf_examples = _dataset_to_frame(load_dataset(DATASET_ID))
        custom = pd.read_csv(custom_csv)
    except Exception as exc:
        raise RuntimeError(f"Could not load injection-classification sources: {exc}") from exc

    required_custom = {"text", "label"}
    missing_custom = required_custom.difference(custom.columns)
    if missing_custom:
        raise ValueError(f"Custom CSV is missing columns: {sorted(missing_custom)}")
    custom = custom.copy()
    custom["text"] = custom["text"].fillna("").astype(str).str.strip()
    custom = custom.loc[custom["text"].ne("")].copy()
    custom["label"] = custom["label"].map(_normalize_label)
    for column, default in (("category", "custom"), ("context", "vulnerability-management text field")):
        if column not in custom:
            custom[column] = default
        custom[column] = custom[column].fillna(default).astype(str)
    custom["source"] = "custom"
    custom = custom[["text", "label", "category", "context", "source"]]

    combined = pd.concat([hf_examples, custom], ignore_index=True)
    combined["_dedupe_key"] = combined["text"].str.casefold().str.replace(r"\s+", " ", regex=True).str.strip()
    combined = combined.drop_duplicates("_dedupe_key", keep="first").drop(columns="_dedupe_key")
    if combined["label"].nunique() != 2:
        raise ValueError("Combined examples must contain both benign (0) and injection (1) labels")
    if combined["label"].value_counts().min() < 3:
        raise ValueError("Need at least three examples of each class for stratified splitting")

    train, remainder = train_test_split(
        combined, test_size=0.30, random_state=random_seed, stratify=combined["label"]
    )
    validation, test = train_test_split(
        remainder, test_size=0.50, random_state=random_seed, stratify=remainder["label"]
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    splits = {"train": train, "val": validation, "test": test}
    for split_name, split_frame in splits.items():
        destination = output_dir / f"injection_{split_name}.csv"
        split_frame.to_csv(destination, index=False)

    print(f"Combined unique examples: {len(combined):,}")
    for split_name, split_frame in splits.items():
        counts = split_frame["label"].value_counts().reindex([0, 1], fill_value=0)
        balance = (counts / len(split_frame)).round(3).to_dict()
        print(f"{split_name}: {len(split_frame):,} total; class counts (0=benign, 1=injection) {counts.to_dict()}; balance {balance}")
    return splits


if __name__ == "__main__":
    try:
        prepare_data()
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"Injection data preparation failed: {exc}") from exc
