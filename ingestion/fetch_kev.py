"""Download the CISA Known Exploited Vulnerabilities catalog."""

from pathlib import Path

import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv"
KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}


def fetch_kev(output_dir=None):
    output_dir = Path(output_dir or Path(__file__).resolve().parents[1] / "data/raw/kev")
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        response = requests.get(KEV_URL, headers=HEADERS, timeout=30)
        response.raise_for_status()
        destination = output_dir / "known_exploited_vulnerabilities.csv"
    except requests.RequestException as csv_error:
        try:
            response = requests.get(KEV_JSON_URL, headers=HEADERS, timeout=30)
            response.raise_for_status()
        except requests.RequestException as json_error:
            raise requests.RequestException(
                f"Both CISA KEV feeds failed; CSV error: {csv_error}; JSON error: {json_error}"
            ) from json_error
        destination = output_dir / "known_exploited_vulnerabilities.json"
    destination.write_bytes(response.content)
    return destination


if __name__ == "__main__":
    try:
        print(f"Saved {fetch_kev()}")
    except (requests.RequestException, OSError) as exc:
        raise SystemExit(f"KEV fetch failed: {exc}") from exc
