"""Download the daily EPSS scores archive."""

from pathlib import Path

import requests

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def fetch_epss(output_dir=None):
    output_dir = Path(output_dir or Path(__file__).resolve().parents[1] / "data/raw/epss")
    output_dir.mkdir(parents=True, exist_ok=True)
    response = requests.get(EPSS_URL, timeout=120)
    response.raise_for_status()
    destination = output_dir / "epss_scores-current.csv.gz"
    destination.write_bytes(response.content)
    return destination


if __name__ == "__main__":
    try:
        print(f"Saved {fetch_epss()}")
    except (requests.RequestException, OSError) as exc:
        raise SystemExit(f"EPSS fetch failed: {exc}") from exc
