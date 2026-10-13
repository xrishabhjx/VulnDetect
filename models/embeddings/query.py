"""Find semantically similar CVEs using the local MiniLM embedding index."""

import json
from pathlib import Path

import numpy as np

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
INDEX_DIR = Path(__file__).resolve().parents[2] / "data/processed/embeddings"
_MODEL = None


def _get_model():
    global _MODEL
    if _MODEL is None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("Install sentence-transformers with `pip install -r requirements.txt`.") from exc
        try:
            _MODEL = SentenceTransformer(MODEL_NAME)
        except Exception as exc:
            raise RuntimeError(f"Could not load local embedding model {MODEL_NAME}: {exc}") from exc
    return _MODEL


def find_similar_cves(query_text: str, top_k: int = 5) -> list[dict]:
    """Return the most similar indexed CVEs by cosine similarity."""
    if not isinstance(query_text, str) or not query_text.strip():
        raise ValueError("query_text must be a non-empty string")
    if top_k < 1:
        raise ValueError("top_k must be at least 1")
    vectors_path = INDEX_DIR / "embeddings.npy"
    mapping_path = INDEX_DIR / "cve_mapping.json"
    if not vectors_path.is_file() or not mapping_path.is_file():
        raise FileNotFoundError(
            f"Embedding index is incomplete in {INDEX_DIR}; run models/embeddings/build_index.py first"
        )
    try:
        index = np.load(vectors_path, allow_pickle=False)
        mapping = json.loads(mapping_path.read_text(encoding="utf-8"))["records"]
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read embedding index from {INDEX_DIR}: {exc}") from exc
    if index.ndim != 2 or len(index) != len(mapping):
        raise ValueError("Embedding index dimensions do not match the CVE mapping")

    model = _get_model()
    try:
        query_vector = np.asarray(
            model.encode([query_text.strip()], convert_to_numpy=True), dtype=np.float32
        ).reshape(1, -1)
    except Exception as exc:
        raise RuntimeError(f"Could not embed query text: {exc}") from exc
    query_norm = np.linalg.norm(query_vector, axis=1, keepdims=True)
    query_vector = np.divide(query_vector, query_norm, out=np.zeros_like(query_vector), where=query_norm != 0)
    if query_vector.shape[1] != index.shape[1]:
        raise ValueError(
            f"Query embedding dimension {query_vector.shape[1]} does not match index dimension {index.shape[1]}"
        )
    similarities = (index @ query_vector.T).ravel()
    best_indices = np.argsort(-similarities, kind="stable")[: min(top_k, len(mapping))]
    return [
        {
            "cve_id": mapping[index_row]["cve_id"],
            "similarity_score": float(similarities[index_row]),
            "description": mapping[index_row]["description"],
        }
        for index_row in best_indices
    ]
