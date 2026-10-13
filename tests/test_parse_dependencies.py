import json

import pytest

from ingestion.fetch_repo_manifest import fetch_manifest_files
from ingestion.parse_dependencies import parse_dependencies


def test_parse_package_json_and_requirements_manifests():
    manifests = {
        "package.json": json.dumps({
            "dependencies": {"express": "^4.18.2", "lodash": "~4.17.21"},
            "devDependencies": {"vite": ">=5.0.0"},
        }),
        "requirements.txt": "requests==2.31.0\npandas>=2.0\n# comment\n",
    }

    assert parse_dependencies(manifests) == [
        {"ecosystem": "npm", "name": "express", "version": "4.18.2"},
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"},
        {"ecosystem": "npm", "name": "vite", "version": "5.0.0"},
        {"ecosystem": "PyPI", "name": "requests", "version": "2.31.0"},
        {"ecosystem": "PyPI", "name": "pandas", "version": "2.0"},
    ]


def test_parse_actual_express_package_json():
    manifests = fetch_manifest_files("https://github.com/expressjs/express")
    if "error" in manifests:
        message = manifests["error"]
        if any(token in message.lower() for token in ("could not reach github", "rate limit")):
            pytest.skip(f"Live GitHub integration test unavailable: {message}")
    assert "package.json" in manifests, manifests.get("error", manifests)

    parsed = parse_dependencies({"package.json": manifests["package.json"]})
    print("First five parsed Express dependencies:", parsed[:5])

    assert len(parsed) >= 10
    assert all(entry["ecosystem"] == "npm" for entry in parsed)
    assert all(isinstance(entry["name"], str) and entry["name"].strip() for entry in parsed)
