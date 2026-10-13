"""Live smoke test for fetching a root manifest from a public GitHub repo."""

import pytest
import requests

from ingestion.fetch_repo_manifest import fetch_manifest_files


def test_fetches_package_json_from_express_repository():
    result = fetch_manifest_files("https://github.com/expressjs/express")

    if "error" in result:
        message = result["error"]
        # GitHub can be inaccessible in offline/CI sandboxes or temporarily rate-limited.
        if any(token in message.lower() for token in ("could not reach github", "rate limit")):
            pytest.skip(f"Live GitHub smoke test unavailable in this environment: {message}")

    assert "package.json" in result, result.get("error", result)
    assert '"name"' in result["package.json"]
    assert result["package.json"].strip()
