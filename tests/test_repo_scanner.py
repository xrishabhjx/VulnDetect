import pytest
from fastapi.testclient import TestClient

import api.main as api_main
import api.repo_scanner as repo_scanner


class StubRiskEngine:
    """Keep this live repository/API integration independent of model artifacts."""

    def assess(self, cve_data, free_text_fields):
        return {
            "risk_probability": 0.9,
            "risk_rating": "CRITICAL",
            "security_flag": "NONE",
            "similar_cves": [],
            "model_version": "test-risk-engine",
            "explanation": "Stub assessment for endpoint integration coverage.",
            "requires_human_review": True,
        }


def test_scan_repo_endpoint_returns_risk_scored_nodegoat_findings(monkeypatch, caplog):
    # NodeGoat is a small, intentionally vulnerable public sample repository
    # whose package.json pins several old dependencies, including marked 0.3.5.
    monkeypatch.setattr(repo_scanner, "RiskEngine", StubRiskEngine)
    monkeypatch.setattr(api_main, "_build_cve_cache", lambda _engine: [])

    with TestClient(api_main.app) as client:
        response = client.post(
            "/scan-repo",
            json={"repo_url": "https://github.com/OWASP/NodeGoat"},
        )

    assert response.status_code == 200, response.text
    payload = response.json()
    if payload.get("error") and "could not reach github" in payload["error"].lower():
        pytest.skip(f"GitHub is unavailable in this environment: {payload['error']}")
    if not payload.get("findings") and any("OSV query failed" in rec.message for rec in caplog.records):
        pytest.skip("OSV.dev is unavailable or rate-limited in this environment.")

    assert payload["repo"] == "https://github.com/OWASP/NodeGoat"
    assert payload["dependencies_scanned"] > 0
    assert payload["vulnerabilities_found"] > 0
    assert payload["findings"]
    assert all(finding["risk_rating"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} for finding in payload["findings"])
    assert all(finding["package"] and finding["version"] for finding in payload["findings"])
    assert all(finding["requires_human_review"] is True for finding in payload["findings"])
