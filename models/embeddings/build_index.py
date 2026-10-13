"""Embed CVE descriptions locally and persist a NumPy cosine-similarity index."""

import json
from pathlib import Path

import numpy as np
import pandas as pd

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def _normalize_rows(vectors):
    vectors = np.asarray(vectors, dtype=np.float32)
    if vectors.ndim != 2:
        raise ValueError(f"Expected a 2-D embedding array, got shape {vectors.shape}")
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    return np.divide(vectors, norms, out=np.zeros_like(vectors), where=norms != 0)


def build_index(dataset_path=None, output_dir=None, model=None, batch_size=64):
    """Create embeddings.npy and cve_mapping.json from the processed dataset."""
    project_root = Path(__file__).resolve().parents[2]
    dataset_path = Path(dataset_path or project_root / "data/processed/vuln_dataset.parquet")
    output_dir = Path(output_dir or project_root / "data/processed/embeddings")
    if not dataset_path.is_file():
        raise FileNotFoundError(f"Processed vulnerability dataset not found: {dataset_path}")
    try:
        frame = pd.read_parquet(dataset_path)
    except (OSError, ImportError, ValueError) as exc:
        raise RuntimeError(f"Could not load vulnerability dataset {dataset_path}: {exc}") from exc
    required = {"cve_id", "description"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing)}")
    frame = frame.dropna(subset=["cve_id", "description"]).copy()
    frame["cve_id"] = frame["cve_id"].astype(str)
    frame["description"] = frame["description"].astype(str).str.strip()
    frame = frame.loc[frame["description"].ne("")].drop_duplicates("cve_id").reset_index(drop=True)
    if frame.empty:
        raise ValueError("No CVE records with non-empty descriptions were found")

    if model is None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("Install sentence-transformers with `pip install -r requirements.txt`.") from exc
        try:
            model = SentenceTransformer(MODEL_NAME)
        except Exception as exc:
            raise RuntimeError(f"Could not load local embedding model {MODEL_NAME}: {exc}") from exc

    try:
        vectors = model.encode(
            frame["description"].tolist(),
            batch_size=batch_size,
            show_progress_bar=True,
            convert_to_numpy=True,
        )
        vectors = _normalize_rows(vectors)
    except Exception as exc:
        raise RuntimeError(f"Could not embed CVE descriptions: {exc}") from exc
    if len(vectors) != len(frame):
        raise ValueError(f"Encoder returned {len(vectors)} vectors for {len(frame)} descriptions")

    output_dir.mkdir(parents=True, exist_ok=True)
    np.save(output_dir / "embeddings.npy", vectors)
    mapping = {
        "model_name": MODEL_NAME,
        "records": [
            {"cve_id": row.cve_id, "description": row.description}
            for row in frame.itertuples(index=False)
        ],
    }
    (output_dir / "cve_mapping.json").write_text(
        json.dumps(mapping, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Indexed {len(frame):,} CVE descriptions in {output_dir}")
    print(f"Embedding dimensions: {vectors.shape[1]}")
    return vectors, mapping["records"]


if __name__ == "__main__":
    try:
        build_index()
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"Embedding index build failed: {exc}") from exc
