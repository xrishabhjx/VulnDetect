import json

import numpy as np

from models.embeddings import query as query_module


class FakeEncoder:
    def encode(self, texts, **kwargs):
        # Both descriptions of the same parser flaw map to the same simple test vector.
        return np.array([[1.0, 0.0] if "parser" in text.lower() else [0.0, 1.0] for text in texts])


def test_similar_description_returns_matching_cve_first(tmp_path, monkeypatch):
    records = [
        {"cve_id": "CVE-2025-1234", "description": "A parser flaw allows remote code execution."},
        {"cve_id": "CVE-2025-5678", "description": "The login page displays an incorrect banner."},
    ]
    np.save(tmp_path / "embeddings.npy", np.array([[1.0, 0.0], [0.0, 1.0]], dtype=np.float32))
    (tmp_path / "cve_mapping.json").write_text(
        json.dumps({"model_name": "test-fake-encoder", "records": records}), encoding="utf-8"
    )
    monkeypatch.setattr(query_module, "INDEX_DIR", tmp_path)
    monkeypatch.setattr(query_module, "_get_model", lambda: FakeEncoder())

    results = query_module.find_similar_cves(
        "A vulnerability in the parser enables remote command execution.", top_k=2
    )

    assert results[0]["cve_id"] == "CVE-2025-1234"
    assert results[0]["similarity_score"] > results[1]["similarity_score"]
