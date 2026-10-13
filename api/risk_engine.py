"""Deterministic risk thresholds with isolated injection screening and context.

Only allowlisted structured CVE fields are used to construct risk-model
features. Free text is passed only to the separate injection classifier and
can set a security flag, but it cannot change risk_probability or risk_rating.
"""

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd

from models.embeddings.query import find_similar_cves

RISK_THRESHOLDS = ((0.75, "CRITICAL"), (0.50, "HIGH"), (0.25, "MEDIUM"), (0.0, "LOW"))
INJECTION_CONFIDENCE_THRESHOLD = 0.70


class RiskEngine:
    """Load trained local models and assess CVE risk without text-score coupling."""

    def __init__(self, risk_model_path=None, injection_model_dir=None):
        project_root = Path(__file__).resolve().parents[1]
        self.risk_model_path = Path(
            risk_model_path or project_root / "models/artifacts/risk_model.joblib"
        )
        self.injection_model_dir = Path(
            injection_model_dir or project_root / "models/injection_classifier/artifacts"
        )
        self._risk_model = None
        self._text_model = None
        self._text_tokenizer = None
        self._cached_model_version = None

    def _load_risk_model(self):
        if self._risk_model is None:
            if not self.risk_model_path.is_file():
                raise FileNotFoundError(
                    f"Risk model not found: {self.risk_model_path}. Run models/train_risk_model.py first."
                )
            try:
                import joblib

                self._risk_model = joblib.load(self.risk_model_path)
            except (OSError, ImportError, ValueError) as exc:
                raise RuntimeError(f"Could not load risk model {self.risk_model_path}: {exc}") from exc
        return self._risk_model

    def _load_injection_model(self):
        if self._text_model is None or self._text_tokenizer is None:
            if not (self.injection_model_dir / "config.json").is_file():
                raise FileNotFoundError(
                    f"Injection classifier not found in {self.injection_model_dir}. "
                    "Run models/injection_classifier/train_classifier.py first."
                )
            try:
                import torch
                from transformers import AutoModelForSequenceClassification, AutoTokenizer

                self._text_tokenizer = AutoTokenizer.from_pretrained(self.injection_model_dir)
                self._text_model = AutoModelForSequenceClassification.from_pretrained(
                    self.injection_model_dir
                )
                self._text_device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                self._text_model.to(self._text_device)
                self._text_model.eval()
            except (ImportError, OSError, ValueError) as exc:
                raise RuntimeError(f"Could not load injection classifier: {exc}") from exc
        return self._text_model, self._text_tokenizer

    def _injection_detected(self, free_text_fields):
        texts = [value.strip() for value in free_text_fields.values()
                 if isinstance(value, str) and value.strip()]
        if not texts:
            return False
        model, tokenizer = self._load_injection_model()
        import torch

        encoded = tokenizer(texts, truncation=True, padding=True, max_length=256, return_tensors="pt")
        encoded = {key: value.to(self._text_device) for key, value in encoded.items()}
        with torch.no_grad():
            probabilities = torch.softmax(model(**encoded).logits, dim=-1)[:, 1]
        return bool(torch.any(probabilities > INJECTION_CONFIDENCE_THRESHOLD).item())

    @staticmethod
    def _structured_features(cve_data, model):
        """Build the trained model's feature schema without consuming any text."""
        # Intentionally allowlist structured attributes. In particular, do not
        # copy `description` or any field from free_text_fields into this frame.
        include_epss = getattr(model, "vulnintel_include_epss", True)
        row = {
            "cvss_v3_score": cve_data.get("cvss_v3_score"),
            "published_date": cve_data.get("published_date"),
            "cwe_id": cve_data.get("cwe_id") or "Unknown",
        }
        if include_epss:
            row["epss_score"] = cve_data.get("epss_score")
        features = pd.DataFrame([row])
        features["cvss_v3_score"] = pd.to_numeric(features["cvss_v3_score"], errors="coerce")
        if include_epss:
            features["epss_score"] = pd.to_numeric(features["epss_score"], errors="coerce")
        published = pd.to_datetime(features["published_date"], errors="coerce", utc=True)
        now = pd.Timestamp.now(tz="UTC")
        features["days_since_published"] = ((now - published).dt.total_seconds() / 86400).clip(lower=0)
        if include_epss:
            features["cvss_epss_interaction"] = features["cvss_v3_score"] * features["epss_score"]
        features["cwe_id"] = features["cwe_id"].astype(str)

        # Text length was a training feature. At inference, use its fitted median
        # as a neutral fixed value rather than letting any description text score.
        description_length = 0.0
        try:
            imputer = model.named_steps["preprocessor"].named_transformers_["numeric"]
            numeric_names = list(model.named_steps["preprocessor"].transformers_[0][2])
            description_length = float(imputer.statistics_[numeric_names.index("description_length")])
        except (AttributeError, KeyError, IndexError, TypeError, ValueError):
            pass
        features["description_length"] = description_length
        columns = ["cvss_v3_score", "days_since_published", "description_length", "cwe_id"]
        if include_epss:
            columns[1:1] = ["epss_score"]
            columns.insert(-1, "cvss_epss_interaction")
        return features[columns]

    @staticmethod
    def _top_contributions(model, features, limit=3):
        """Use per-record XGBoost contributions, with global importance fallback."""
        try:
            preprocessor = model.named_steps["preprocessor"]
            classifier = model.named_steps["classifier"]
            transformed = preprocessor.transform(features)
            import xgboost as xgb

            contributions = classifier.get_booster().predict(
                xgb.DMatrix(transformed), pred_contribs=True
            )[0][:-1]
            names = preprocessor.get_feature_names_out()
            ranked = sorted(zip(names, contributions), key=lambda item: abs(float(item[1])), reverse=True)
            return [
                (str(name).split("__", 1)[-1], float(value))
                for name, value in ranked[:limit]
            ]
        except Exception:
            classifier = getattr(model, "named_steps", {}).get("classifier", model)
            values = np.asarray(getattr(classifier, "feature_importances_", []), dtype=float)
            if not values.size:
                return []
            names = getattr(classifier, "feature_names_in_", [f"feature_{i}" for i in range(len(values))])
            ranked = sorted(zip(names, values), key=lambda item: float(item[1]), reverse=True)
            return [(str(name), float(value)) for name, value in ranked[:limit]]

    @staticmethod
    def _explanation(contributions):
        if not contributions:
            return "Risk probability was produced by the trained structured-feature model; per-feature contributions were unavailable."
        parts = []
        for name, value in contributions:
            direction = "increased" if value > 0 else "decreased" if value < 0 else "influenced"
            readable_name = name.replace("cwe_id_", "CWE ").replace("_", " ")
            parts.append(f"{readable_name} {direction} the model score")
        return "Top model contributions: " + "; ".join(parts) + "."

    def _model_version(self, model):
        if self._cached_model_version is None:
            if self.risk_model_path.is_file():
                digest = hashlib.sha256(self.risk_model_path.read_bytes()).hexdigest()[:12]
                self._cached_model_version = f"risk_model.joblib:{digest}"
            else:
                self._cached_model_version = type(model).__name__
        return self._cached_model_version

    @staticmethod
    def _rating(probability):
        for threshold, rating in RISK_THRESHOLDS:
            if probability >= threshold:
                return rating
        return "LOW"

    def assess(self, cve_data: dict, free_text_fields: dict[str, str]) -> dict:
        """Assess structured CVE risk and separately flag suspicious free text."""
        model = self._load_risk_model()
        features = self._structured_features(cve_data, model)
        try:
            risk_probability = float(np.asarray(model.predict_proba(features))[0, 1])
        except (AttributeError, IndexError, TypeError, ValueError) as exc:
            raise RuntimeError(f"Risk model could not produce a positive-class probability: {exc}") from exc
        risk_probability = min(1.0, max(0.0, risk_probability))
        security_flag = "INJECTION_DETECTED" if self._injection_detected(free_text_fields or {}) else "NONE"

        description = cve_data.get("description")
        if isinstance(description, str) and description.strip():
            try:
                similar_cves = find_similar_cves(description, top_k=5)
            except FileNotFoundError:
                similar_cves = []
        else:
            similar_cves = []

        contributions = self._top_contributions(model, features)
        return {
            "risk_probability": risk_probability,
            "risk_rating": self._rating(risk_probability),
            "security_flag": security_flag,
            "similar_cves": similar_cves,
            "model_version": self._model_version(model),
            "explanation": self._explanation(contributions),
            "requires_human_review": True,
        }
