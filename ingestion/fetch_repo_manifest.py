"""Fetch common dependency manifests from a public GitHub repository."""

from __future__ import annotations

import time
from urllib.parse import urlparse

import requests

GITHUB_API = "https://api.github.com"
MANIFESTS = ("package.json", "requirements.txt", "pyproject.toml", "pom.xml")
REQUEST_TIMEOUT = 15
MAX_RETRIES = 3
RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}


def _parse_repo_url(repo_url: str) -> tuple[str, str] | None:
    """Return the owner and repository name for a GitHub repository URL."""
    try:
        parsed = urlparse(repo_url.strip())
    except (AttributeError, ValueError):
        return None

    if parsed.scheme not in {"https", "http"} or parsed.netloc.lower() != "github.com":
        return None

    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        return None

    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return None
    return owner, repo


def _get_with_retry(url: str, headers: dict[str, str]) -> requests.Response:
    """GET a GitHub API URL, retrying transient network and server failures."""
    last_error: requests.RequestException | None = None
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            last_error = exc
            if attempt == MAX_RETRIES - 1:
                raise
            time.sleep(0.5 * (2**attempt))
            continue

        if response.status_code not in RETRYABLE_STATUS_CODES:
            return response

        if attempt == MAX_RETRIES - 1:
            return response

        retry_after = response.headers.get("Retry-After")
        try:
            delay = float(retry_after) if retry_after else 0.5 * (2**attempt)
        except ValueError:
            delay = 0.5 * (2**attempt)
        time.sleep(max(0.0, min(delay, 10.0)))

    # The loop either returns or raises. This is defensive for static analysis.
    if last_error is not None:
        raise last_error
    raise requests.RequestException(f"GitHub request failed: {url}")


def fetch_manifest_files(
    repo_url: str, github_token: str | None = None
) -> dict[str, str]:
    """Return common root-level manifests from a GitHub repository.

    Errors are returned as ``{"error": "..."}`` so callers can display a
    useful message for malformed URLs, private/missing repositories, API
    limits, network failures, or repositories without supported manifests.
    """
    parsed_repo = _parse_repo_url(repo_url)
    if parsed_repo is None:
        return {"error": "Invalid GitHub repository URL. Expected https://github.com/owner/repo."}

    owner, repo = parsed_repo
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "VulnDetect-repository-manifest-fetcher",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    root_url = f"{GITHUB_API}/repos/{owner}/{repo}/contents"
    try:
        response = _get_with_retry(root_url, headers)
    except requests.RequestException as exc:
        return {"error": f"Could not reach GitHub while checking {owner}/{repo}: {exc}"}

    if response.status_code == 404:
        return {
            "error": (
                f"Repository {owner}/{repo} was not found or is private. "
                "Public repositories can be fetched without authentication."
            )
        }
    if response.status_code in {403, 429}:
        return {
            "error": (
                "GitHub API rate limit or access restriction reached. "
                "Retry later or pass a GitHub personal access token as github_token."
            )
        }
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        return {"error": f"GitHub could not list the root of {owner}/{repo}: {exc}"}

    try:
        root_entries = response.json()
    except ValueError as exc:
        return {"error": f"GitHub returned invalid JSON for {owner}/{repo}: {exc}"}
    if not isinstance(root_entries, list):
        return {"error": f"GitHub returned an unexpected root listing for {owner}/{repo}."}

    available = {
        entry.get("name")
        for entry in root_entries
        if isinstance(entry, dict) and entry.get("type") == "file"
    }
    manifest_names = [name for name in MANIFESTS if name in available]
    if not manifest_names:
        return {
            "error": (
                f"Repository {owner}/{repo} has none of the supported root manifests: "
                f"{', '.join(MANIFESTS)}."
            )
        }

    manifests: dict[str, str] = {}
    raw_headers = {**headers, "Accept": "application/vnd.github.raw+json"}
    for filename in manifest_names:
        url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{filename}"
        try:
            file_response = _get_with_retry(url, raw_headers)
        except requests.RequestException as exc:
            return {"error": f"Could not download {filename} from {owner}/{repo}: {exc}"}

        if file_response.status_code in {403, 429}:
            return {
                "error": (
                    "GitHub API rate limit or access restriction reached while downloading "
                    f"{filename}. Retry later or pass a GitHub token as github_token."
                )
            }
        try:
            file_response.raise_for_status()
        except requests.HTTPError as exc:
            return {"error": f"Could not download {filename} from {owner}/{repo}: {exc}"}
        manifests[filename] = file_response.text

    return manifests


if __name__ == "__main__":
    import argparse
    import os

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_url", help="GitHub repository URL")
    args = parser.parse_args()
    result = fetch_manifest_files(args.repo_url, github_token=os.environ.get("GITHUB_TOKEN"))
    for name, content in result.items():
        if name == "error":
            print(f"Error: {content}")
        else:
            print(f"Fetched {name} ({len(content)} characters)")
