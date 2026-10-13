"""Fetch and archive paginated CVE responses from the NVD API."""

import json
import os
import time
from pathlib import Path

import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000
MAX_RETRIES = 5


def fetch_nvd(output_dir=None, api_key=None, start_index=0, max_results=None):
    output_dir = Path(output_dir or Path(__file__).resolve().parents[1] / "data/raw/nvd")
    output_dir.mkdir(parents=True, exist_ok=True)
    headers = {"apiKey": api_key} if api_key else {}
    start = start_index
    saved = []

    while True:
        params = {"startIndex": start, "resultsPerPage": PAGE_SIZE}
        for attempt in range(MAX_RETRIES):
            try:
                response = requests.get(API_URL, params=params, headers=headers, timeout=60)
                if response.status_code in (403, 429) or response.status_code >= 500:
                    if attempt == MAX_RETRIES - 1:
                        response.raise_for_status()
                    retry_after = response.headers.get("Retry-After")
                    delay = float(retry_after) if retry_after else min(2**attempt, 60)
                    time.sleep(delay)
                    continue
                response.raise_for_status()
                break
            except requests.RequestException:
                if attempt == MAX_RETRIES - 1:
                    raise
                time.sleep(min(2**attempt, 60))

        payload = response.json()
        path = output_dir / f"nvd_start_{start:08d}.json"
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        saved.append(path)

        total = int(payload.get("totalResults", 0))
        page_count = len(payload.get("vulnerabilities", []))
        start += page_count
        if not page_count or start >= total or (max_results and start - start_index >= max_results):
            break
        # NVD asks clients without an API key to keep requests at least six seconds apart.
        time.sleep(0.6 if api_key else 6.0)
    return saved


if __name__ == "__main__":
    try:
        api_key = os.environ.get("NVD_API_KEY")
        paths = fetch_nvd(api_key=api_key)
        print(f"Saved {len(paths)} NVD response page(s).")
    except (requests.RequestException, OSError, ValueError) as exc:
        raise SystemExit(f"NVD fetch failed: {exc}") from exc
