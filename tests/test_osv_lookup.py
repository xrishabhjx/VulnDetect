import pytest

from models.osv_lookup import lookup_vulnerabilities


def test_known_vulnerable_lodash_version_has_osv_finding(caplog):
    findings = lookup_vulnerabilities([
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.11"}
    ])

    if not findings and any("OSV query failed" in record.message for record in caplog.records):
        pytest.skip("OSV.dev is unavailable or rate-limited in this environment.")

    assert findings, "Expected OSV to report vulnerabilities for lodash 4.17.11"
    assert any(item["cve_id"] == "CVE-2019-10744" for item in findings)
    assert all(item["package"] == "lodash" for item in findings)
    assert all(item["version"] == "4.17.11" for item in findings)
    assert all(item["osv_id"] and isinstance(item["summary"], str) for item in findings)
