"""Fine-tune DistilBERT to distinguish prompt injection from benign text."""

import json
from pathlib import Path
import time

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score

MODEL_NAME = "distilbert-base-uncased"
MAX_LENGTH = 256
RANDOM_SEED = 42


def _load_split(path):
    if not path.is_file():
        raise FileNotFoundError(f"Required split not found: {path}. Run prepare_data.py first.")
    frame = pd.read_csv(path)
    if not {"text", "label"}.issubset(frame.columns):
        raise ValueError(f"Split {path} must have text and label columns")
    frame = frame.dropna(subset=["text", "label"])
    frame["text"] = frame["text"].astype(str)
    frame["label"] = pd.to_numeric(frame["label"], errors="coerce")
    frame = frame.dropna(subset=["label"])
    frame["label"] = frame["label"].astype(int)
    if frame.empty or not set(frame["label"].unique()).issubset({0, 1}):
        raise ValueError(f"Split {path} must contain examples labeled 0 (benign) or 1 (injection)")
    return frame


def train_classifier(train_path=None, val_path=None, artifacts_dir=None, epochs=4):
    """Fine-tune for up to four epochs, stopping when validation F1 plateaus."""
    project_root = Path(__file__).resolve().parents[2]
    processed_dir = project_root / "data/processed"
    train_path = Path(train_path or processed_dir / "injection_train.csv")
    val_path = Path(val_path or processed_dir / "injection_val.csv")
    artifacts_dir = Path(artifacts_dir or Path(__file__).resolve().parent / "artifacts")
    if epochs < 2 or epochs > 4:
        raise ValueError("epochs must be between 2 and 4")

    try:
        import torch
        from torch.utils.data import Dataset
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            DataCollatorWithPadding,
            EarlyStoppingCallback,
            Trainer,
            TrainerCallback,
            TrainingArguments,
            set_seed,
        )
    except ImportError as exc:
        raise RuntimeError("Install torch and transformers with `pip install -r requirements.txt`.") from exc

    cuda_available = torch.cuda.is_available()
    device_name = "CUDA GPU" if cuda_available else "CPU"
    print(f"torch.cuda.is_available(): {cuda_available} — training device: {device_name}")
    train_frame = _load_split(train_path)
    val_frame = _load_split(val_path)
    if train_frame["label"].nunique() != 2 or val_frame["label"].nunique() != 2:
        raise ValueError("Train and validation splits must each contain both classes")
    set_seed(RANDOM_SEED)

    try:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
        model = AutoModelForSequenceClassification.from_pretrained(
            MODEL_NAME,
            num_labels=2,
            id2label={0: "BENIGN", 1: "INJECTION"},
            label2id={"BENIGN": 0, "INJECTION": 1},
        )
    except Exception as exc:
        raise RuntimeError(f"Could not load pretrained model {MODEL_NAME}: {exc}") from exc

    class EncodedTextDataset(Dataset):
        def __init__(self, frame):
            self.encodings = tokenizer(
                frame["text"].tolist(), truncation=True, max_length=MAX_LENGTH
            )
            self.labels = frame["label"].tolist()

        def __len__(self):
            return len(self.labels)

        def __getitem__(self, index):
            item = {key: torch.tensor(values[index]) for key, values in self.encodings.items()}
            item["labels"] = torch.tensor(self.labels[index], dtype=torch.long)
            return item

    train_dataset = EncodedTextDataset(train_frame)
    val_dataset = EncodedTextDataset(val_frame)

    def compute_metrics(eval_prediction):
        logits, labels = eval_prediction
        predictions = np.argmax(logits, axis=-1)
        return {
            "accuracy": float(accuracy_score(labels, predictions)),
            "f1": float(f1_score(labels, predictions, zero_division=0)),
        }

    artifacts_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_dir = artifacts_dir / "checkpoints"

    class TrainingProgressCallback(TrainerCallback):
        """Print training loss every 20 steps and estimate duration after epoch 1."""

        def __init__(self):
            self.started_at = None
            self.eta_printed = False

        @staticmethod
        def _duration(seconds):
            seconds = max(0, int(seconds))
            minutes, remaining = divmod(seconds, 60)
            hours, minutes = divmod(minutes, 60)
            return f"{hours:d}h {minutes:02d}m {remaining:02d}s" if hours else f"{minutes:02d}m {remaining:02d}s"

        def on_train_begin(self, args, state, control, **kwargs):
            self.started_at = time.monotonic()
            return control

        def on_log(self, args, state, control, logs=None, **kwargs):
            logs = logs or {}
            step = int(state.global_step or 0)
            if "loss" in logs and step and step % 20 == 0:
                elapsed = time.monotonic() - self.started_at
                print(
                    f"Training progress: step {step}/{state.max_steps} | "
                    f"loss {float(logs['loss']):.4f} | elapsed {self._duration(elapsed)}",
                    flush=True,
                )
            return control

        def on_epoch_end(self, args, state, control, **kwargs):
            if not self.eta_printed and state.epoch is not None and state.epoch >= 1:
                elapsed = time.monotonic() - self.started_at
                steps_done = int(state.global_step or 0)
                total_steps = int(state.max_steps or 0)
                if steps_done and total_steps:
                    estimated_total = elapsed / steps_done * total_steps
                    remaining = max(0.0, estimated_total - elapsed)
                    print(
                        "First epoch complete: "
                        f"estimated total training time {self._duration(estimated_total)} "
                        f"({self._duration(remaining)} remaining, based on {steps_done} steps so far).",
                        flush=True,
                    )
                self.eta_printed = True
            return control

    training_args = TrainingArguments(
        output_dir=str(checkpoint_dir),
        num_train_epochs=epochs,
        learning_rate=2e-5,
        weight_decay=0.01,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=16,
        eval_strategy="epoch",
        save_strategy="epoch",
        logging_strategy="steps",
        logging_steps=20,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        save_total_limit=2,
        report_to="none",
        seed=RANDOM_SEED,
        data_seed=RANDOM_SEED,
    )
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        processing_class=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer=tokenizer),
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=2), TrainingProgressCallback()],
    )
    trainer.train()
    trainer.save_model(str(artifacts_dir))
    tokenizer.save_pretrained(artifacts_dir)

    # Trainer logs contain one training loss and validation loss/accuracy/F1 row per epoch.
    log_history = [
        {key: (float(value) if isinstance(value, (np.floating, np.integer)) else value)
         for key, value in event.items()}
        for event in trainer.state.log_history
    ]
    (artifacts_dir / "training_history.json").write_text(
        json.dumps(log_history, indent=2, default=str) + "\n", encoding="utf-8"
    )
    print("\nEpoch logs (training loss and validation loss/accuracy/F1):")
    for event in log_history:
        if "loss" in event or "eval_loss" in event:
            print(json.dumps(event, sort_keys=True))
    print(f"\nSaved best validation-F1 model and tokenizer to {artifacts_dir}")
    return trainer


if __name__ == "__main__":
    try:
        train_classifier()
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"Classifier training failed: {exc}") from exc
