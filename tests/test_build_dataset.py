import gzip
import json

from ingestion.build_dataset import COLUMNS, build_dataset


def test_build_dataset_from_sample_sources(tmp_path):
    data_dir = tmp_path / "data"
    nvd_dir = data_dir / "raw" / "nvd"
    kev_dir = data_dir / "raw" / "kev"
    epss_dir = data_dir / "raw" / "epss"
    nvd_dir.mkdir(parents=True)
    kev_dir.mkdir(parents=True)
    epss_dir.mkdir(parents=True)
    (nvd_dir / "sample.json").write_text(json.dumps({
        "vulnerabilities": [{"cve": {
            "id": "CVE-2025-1234",
            "published": "2025-01-02T03:04:05.000Z",
            "descriptions": [{"lang": "en", "value": "Sample vulnerability."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {
                "baseScore": 8.1, "vectorString": "CVSS:3.1/AV:N/AC:L"
            }}]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
        }}]
    }), encoding="utf-8")
    (kev_dir / "kev.csv").write_text(
        "cveID,dateAdded\nCVE-2025-1234,2025-01-03\n", encoding="utf-8"
    )
    with gzip.open(epss_dir / "scores.csv.gz", "wt", encoding="utf-8") as epss:
        epss.write("# model version: sample\ncve,epss,percentile\nCVE-2025-1234,0.42,0.91\n")

    result = build_dataset(data_dir=data_dir)

    assert not result.empty
    assert result.columns.tolist() == COLUMNS
    assert result.loc[0, "cve_id"] == "CVE-2025-1234"
    assert result.loc[0, "in_kev"] is True or bool(result.loc[0, "in_kev"])
    assert result.loc[0, "epss_score"] == 0.42
    assert (data_dir / "processed" / "vuln_dataset.parquet").exists()
