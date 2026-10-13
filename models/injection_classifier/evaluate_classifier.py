"""Evaluate the fine-tuned classifier against a small regex detector."""

import json
import re
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

RANDOM_SEED = 42
REGEX_PATTERNS = [
    r"\bignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+instructions?\b",
    r"\bdisregard\b",
    r"\bsystem\s+prompt\b",
    r"\b(?:reveal|show|print|quote|disclose)\b.{0,50}\b(?:hidden|system|developer)\s+(?:prompt|instructions?|message)\b",
    r"\b(?:override|forget)\b.{0,50}\b(?:instructions?|rules|policy|directions)\b",
]
REGEX = re.compile("|".join(f"(?:{pattern})" for pattern in REGEX_PATTERNS), re.IGNORECASE)


def _metrics(y_true, y_pred, y_score):
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_score)),
        "pr_auc": float(average_precision_score(y_true, y_score)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }


def evaluate_classifier(test_path=None, artifacts_dir=None, output_path=None):
    project_root = Path(__file__).resolve().parents[2]
    test_path = Path(test_path or project_root / "data/processed/injection_test.csv")
    artifacts_dir = Path(artifacts_dir or Path(__file__).resolve().parent / "artifacts")
    output_path = Path(output_path or project_root / "results/injection_classifier_evaluation.json")
    if not test_path.is_file():
        raise FileNotFoundError(f"Held-out test split not found: {test_path}. Run prepare_data.py first.")
    if not (artifacts_dir / "config.json").is_file():
        raise FileNotFoundError(f"Trained classifier not found in {artifacts_dir}. Run train_classifier.py first.")
    frame = pd.read_csv(test_path)
    if not {"text", "label"}.issubset(frame.columns):
        raise ValueError(f"Test split {test_path} must have text and label columns")
    frame = frame.dropna(subset=["text", "label"]).copy()
    frame["label"] = pd.to_numeric(frame["label"], errors="coerce")
    frame = frame.dropna(subset=["label"])
    if frame.empty or not set(frame["label"].astype(int).unique()).issubset({0, 1}):
        raise ValueError("Test split must contain labels 0 (benign) and 1 (injection)")
    y_true = frame["label"].astype(int).to_numpy()

    try:
        import torch
        from torch.utils.data import DataLoader, Dataset
        from transformers import AutoModelForSequenceClassification, AutoTokenizer, DataCollatorWithPadding
    except ImportError as exc:
        raise RuntimeError("Install torch and transformers with `pip install -r requirements.txt`.") from exc
    try:
        tokenizer = AutoTokenizer.from_pretrained(artifacts_dir)
        model = AutoModelForSequenceClassification.from_pretrained(artifacts_dir)
    except Exception as exc:
        raise RuntimeError(f"Could not load saved classifier from {artifacts_dir}: {exc}") from exc

    class TestTextDataset(Dataset):
        def __init__(self, texts):
            self.encodings = tokenizer(texts, truncation=True, max_length=256)

        def __len__(self):
            return len(self.encodings["input_ids"])

        def __getitem__(self, index):
            return {key: torch.tensor(values[index]) for key, values in self.encodings.items()}

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    loader = DataLoader(
        TestTextDataset(frame["text"].astype(str).tolist()),
        batch_size=16,
        shuffle=False,
        collate_fn=DataCollatorWithPadding(tokenizer=tokenizer, return_tensors="pt"),
    )
    classifier_predictions = []
    classifier_scores = []
    with torch.no_grad():
        for batch in loader:
            batch = {key: value.to(device) for key, value in batch.items()}
            logits = model(**batch).logits
            probabilities = torch.softmax(logits, dim=-1)[:, 1]
            classifier_scores.extend(probabilities.cpu().tolist())
            classifier_predictions.extend((probabilities >= 0.5).long().cpu().tolist())
    regex_predictions = frame["text"].astype(str).map(lambda text: int(bool(REGEX.search(text)))).to_numpy()

    results = {
        "test_rows": int(len(frame)),
        "class_counts": {str(int(label)): int(count) for label, count in frame["label"].astype(int).value_counts().sort_index().items()},
        "label_mapping": {"0": "benign", "1": "injection"},
        "trained_classifier": _metrics(y_true, np.asarray(classifier_predictions), np.asarray(classifier_scores)),
        "regex_baseline": _metrics(y_true, regex_predictions, regex_predictions.astype(float)),
        "regex_patterns": REGEX_PATTERNS,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")

    print(f"Test examples: {len(frame)}")
    print("\n| Detector | Precision | Recall | F1 | Confusion matrix [[TN, FP], [FN, TP]] |")
    print("|---|---:|---:|---:|---|")
    for name, key in (("Trained DistilBERT", "trained_classifier"), ("Regex baseline", "regex_baseline")):
        metrics = results[key]
        print(
            f"| {name} | {metrics['precision']:.3f} | {metrics['recall']:.3f} | "
            f"{metrics['f1']:.3f} | {metrics['confusion_matrix']} |"
        )
    print(f"\nSaved evaluation to {output_path}")
    return results


if __name__ == "__main__":
    try:
        evaluate_classifier()
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"Classifier evaluation failed: {exc}") from exc
