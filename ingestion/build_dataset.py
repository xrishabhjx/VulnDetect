"""Normalize archived NVD, CISA KEV, and EPSS sources into one dataset."""

import gzip
import json
from pathlib import Path

import pandas as pd

COLUMNS = [
    "cve_id", "cvss_v3_score", "cvss_vector", "published_date", "cwe_id",
    "description", "epss_score", "in_kev", "kev_date_added",
]


def _nvd_rows(raw_dir):
    rows = {}
    for path in sorted(raw_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not read NVD JSON {path}: {exc}") from exc
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            metrics = cve.get("metrics", {})
            score = vector = None
            for metric_name in ("cvssMetricV31", "cvssMetricV30"):
                metrics_list = metrics.get(metric_name, [])
                if metrics_list:
                    cvss = metrics_list[0].get("cvssData", {})
                    score, vector = cvss.get("baseScore"), cvss.get("vectorString")
                    break
            cwe = None
            for weakness in cve.get("weaknesses", []):
                for description in weakness.get("description", []):
                    value = description.get("value", "")
                    if value.startswith("CWE-"):
                        cwe = value
                        break
                if cwe:
                    break
            description = next(
                (d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                None,
            )
            rows[cve_id] = {
                "cve_id": cve_id,
                "cvss_v3_score": score,
                "cvss_vector": vector,
                "published_date": cve.get("published"),
                "cwe_id": cwe,
                "description": description,
            }
    return rows


def _find_one(folder, pattern, label):
    files = sorted(folder.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No {label} file matching {pattern} in {folder}")
    return files[0]


def _kev_frame(folder):
    """Read whichever KEV format was downloaded most recently."""
    csv_files = sorted(folder.glob("*.csv")) if folder.exists() else []
    json_files = sorted(folder.glob("*.json")) if folder.exists() else []
    candidates = csv_files + json_files
    if candidates:
        path = max(candidates, key=lambda item: item.stat().st_mtime)
        if path.suffix.lower() == ".csv":
            try:
                return pd.read_csv(path), path
            except (OSError, pd.errors.ParserError) as exc:
                raise ValueError(f"Could not parse KEV file {path}: {exc}") from exc
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            records = payload.get("vulnerabilities", [])
            if not isinstance(records, list):
                raise ValueError("expected a vulnerabilities list")
            return pd.DataFrame(records), path
        except (OSError, json.JSONDecodeError, AttributeError, ValueError) as exc:
            raise ValueError(f"Could not parse KEV JSON {path}: {exc}") from exc
    raise FileNotFoundError(f"No KEV CSV or JSON catalog found in {folder}")


def _epss_frame(path):
    opener = gzip.open if path.suffix == ".gz" else open
    try:
        with opener(path, "rt", encoding="utf-8-sig", newline="") as source:
            # EPSS files may start with comment lines containing the score date.
            while True:
                position = source.tell()
                line = source.readline()
                if not line or not line.lstrip().startswith("#"):
                    source.seek(position)
                    break
            frame = pd.read_csv(source)
    except (OSError, EOFError, pd.errors.ParserError) as exc:
        raise ValueError(f"Could not parse EPSS file {path}: {exc}") from exc
    if not {"cve", "epss"}.issubset(frame.columns):
        raise ValueError(f"EPSS file {path} must contain cve and epss columns")
    return frame.rename(columns={"cve": "cve_id", "epss": "epss_score"})[["cve_id", "epss_score"]]


def build_dataset(data_dir=None, output_path=None):
    """Build and save the normalized DataFrame; paths are overridable for tests."""
    root = Path(data_dir or Path(__file__).resolve().parents[1] / "data")
    nvd = _nvd_rows(root / "raw/nvd")
    kev_frame, kev_path = _kev_frame(root / "raw/kev")
    epss_path = _find_one(root / "raw/epss", "*.csv*", "EPSS CSV")
    required_kev = {"cveID", "dateAdded"}
    if not required_kev.issubset(kev_frame.columns):
        raise ValueError(f"KEV file {kev_path} must contain cveID and dateAdded columns")

    frame = pd.DataFrame(list(nvd.values()), columns=COLUMNS[:6])
    frame = frame.merge(_epss_frame(epss_path), on="cve_id", how="left")
    kev_frame = kev_frame.rename(columns={"cveID": "cve_id", "dateAdded": "kev_date_added"})
    kev_frame = kev_frame[["cve_id", "kev_date_added"]].drop_duplicates("cve_id")
    frame = frame.merge(kev_frame, on="cve_id", how="left")
    frame["in_kev"] = frame["kev_date_added"].notna()
    frame["published_date"] = pd.to_datetime(frame["published_date"], errors="coerce", utc=True)
    frame["kev_date_added"] = pd.to_datetime(frame["kev_date_added"], errors="coerce").dt.date
    frame["epss_score"] = pd.to_numeric(frame["epss_score"], errors="coerce")
    frame["cvss_v3_score"] = pd.to_numeric(frame["cvss_v3_score"], errors="coerce")
    frame = frame[COLUMNS]

    destination = Path(output_path or root / "processed/vuln_dataset.parquet")
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        frame.to_parquet(destination, index=False)
    except (ImportError, OSError, ValueError) as exc:
        raise RuntimeError(f"Could not write parquet dataset to {destination}: {exc}") from exc
    _print_summary(frame)
    return frame


def _print_summary(frame):
    print(f"Rows: {len(frame):,}")
    valid_dates = frame["published_date"].dropna()
    if valid_dates.empty:
        print("Published date range: unavailable")
    else:
        print(f"Published date range: {valid_dates.min().date()} to {valid_dates.max().date()}")
    pct_kev = 100 * frame["in_kev"].mean() if len(frame) else 0.0
    print(f"In KEV: {pct_kev:.2f}%")
    print("EPSS score distribution:")
    print(frame["epss_score"].describe().to_string())


if __name__ == "__main__":
    try:
        build_dataset()
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"Dataset build failed: {exc}") from exc
