"""Connect repository manifests to OSV findings and VulnDetect risk scores."""

from __future__ import annotations

import logging
import math
from pathlib import Path
from typing import Any

import pandas as pd

from api.risk_engine import RiskEngine
from ingestion.fetch_repo_manifest import fetch_manifest_files
from ingestion.parse_dependencies import parse_dependencies
from models.osv_lookup import lookup_vulnerabilities

logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = PROJECT_ROOT / "data/processed/vuln_dataset.parquet"


def _cvss_v3_score(vector: str) -> float | None:
    """Calculate the CVSS v3 base score from an OSV CVSS vector, if supported."""
    try:
        version, *metrics = vector.split("/")
        if version not in {"CVSS:3.0", "CVSS:3.1"}:
            return None
        values = dict(metric.split(":", 1) for metric in metrics if ":" in metric)
        scope = values["S"]
        av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}[values["AV"]]
        ac = {"L": 0.77, "H": 0.44}[values["AC"]]
        ui = {"N": 0.85, "R": 0.62}[values["UI"]]
        pr_values = {"N": 0.85, "L": 0.62, "H": 0.27} if scope == "U" else {"N": 0.85, "L": 0.68, "H": 0.50}
        pr = pr_values[values["PR"]]
        impact_values = {"H": 0.56, "L": 0.22, "N": 0.0}
        confidentiality = impact_values[values["C"]]
        integrity = impact_values[values["I"]]
        availability = impact_values[values["A"]]
    except (KeyError, TypeError, ValueError):
        return None

    impact_subscore = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability)
    if scope == "U":
        impact = 6.42 * impact_subscore
    elif version == "CVSS:3.1":
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15
    else:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore * 0.9731 - 0.02) ** 13
    if impact <= 0:
        return 0.0

    exploitability = 8.22 * av * ac * pr * ui
    score = min(10.0, impact + exploitability if scope == "U" else 1.08 * (impact + exploitability))
    return math.ceil(score * 10 - 1e-10) / 10


def _osv_severity_data(severity: Any) -> tuple[float | None, str | None, list]:
    """Extract a numeric CVSS score, vector, and original OSV severity values."""
    if not isinstance(severity, list):
        return None, None, []
    for entry in severity:
        if not isinstance(entry, dict):
            continue
        severity_type = str(entry.get("type", "")).upper()
        raw_score = entry.get("score")
        if "CVSS" not in severity_type or not isinstance(raw_score, str):
            continue
        if raw_score.startswith("CVSS:"):
            return _cvss_v3_score(raw_score), raw_score, severity
        try:
            numeric_score = float(raw_score)
        except ValueError:
            continue
        if 0 <= numeric_score <= 10:
            return numeric_score, None, severity
    return None, None, severity


def _load_local_dataset() -> pd.DataFrame | None:
    if not DATASET_PATH.is_file():
        return None
    try:
        frame = pd.read_parquet(DATASET_PATH)
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Could not read local vulnerability dataset {DATASET_PATH}: {exc}") from exc
    if "cve_id" not in frame.columns:
        raise RuntimeError(f"Local vulnerability dataset has no cve_id column: {DATASET_PATH}")
    return frame


def _row_value(row: pd.Series | None, key: str, default=None):
    if row is None:
        return default
    value = row.get(key, default)
    if value is None or (not isinstance(value, (list, dict)) and pd.isna(value)):
        return default
    return value


def scan_repository(repo_url: str) -> dict:
    """Fetch root manifests, query OSV, enrich matches, and assess each CVE.

    Risk calculations remain delegated to ``RiskEngine.assess``.
    """
    manifests = fetch_manifest_files(repo_url)
    if "error" in manifests:
        return {
            "repo": repo_url,
            "dependencies_scanned": 0,
            "vulnerabilities_found": 0,
            "findings": [],
            "error": manifests["error"],
        }

    dependencies = parse_dependencies(manifests)
    osv_findings = lookup_vulnerabilities(dependencies)
    local_data = _load_local_dataset()
    engine = RiskEngine()

    # The local dataset is relatively large. Index it once by normalized CVE ID
    # instead of repeatedly scanning it for every package advisory.
    local_by_cve: dict[str, pd.Series] = {}
    if local_data is not None:
        for _, row in local_data.dropna(subset=["cve_id"]).iterrows():
            local_by_cve.setdefault(str(row["cve_id"]).upper(), row)

    findings = []
    for osv_finding in osv_findings:
        cve_id = str(osv_finding.get("cve_id") or "").upper()
        local_row = local_by_cve.get(cve_id) if cve_id else None
        severity_score, severity_vector, osv_severity = _osv_severity_data(
            osv_finding.get("severity", [])
        )

        if local_row is not None:
            cve_data = {
                "cve_id": cve_id,
                "cvss_v3_score": _row_value(local_row, "cvss_v3_score"),
                "cvss_vector": _row_value(local_row, "cvss_vector"),
                "epss_score": _row_value(local_row, "epss_score"),
                "published_date": _row_value(local_row, "published_date"),
                "cwe_id": _row_value(local_row, "cwe_id"),
                "description": _row_value(local_row, "description") or osv_finding.get("summary", ""),
            }
            source = "local_dataset"
        else:
            cve_data = {
                "cve_id": cve_id or None,
                "cvss_v3_score": severity_score,
                "cvss_vector": severity_vector,
                "epss_score": None,
                "published_date": None,
                "cwe_id": None,
                "description": osv_finding.get("summary", ""),
            }
            source = "osv_fallback"

        summary_text = str(osv_finding.get("summary") or "")
        assessment = engine.assess(
            cve_data,
            {"osv_summary": summary_text} if summary_text else {},
        )
        findings.append({
            **assessment,
            "package": osv_finding.get("package", ""),
            "version": osv_finding.get("version", ""),
            "cve_id": cve_id,
            "osv_id": osv_finding.get("osv_id", ""),
            "source": source,
            "osv_severity": osv_severity,
        })

    return {
        "repo": repo_url,
        "dependencies_scanned": len(dependencies),
        "vulnerabilities_found": len(findings),
        "findings": findings,
    }
