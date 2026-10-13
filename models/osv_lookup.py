"""Query OSV.dev for known vulnerabilities affecting package versions."""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Mapping

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT = 15
MAX_RETRIES = 3
REQUEST_DELAY_SECONDS = 0.1
RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
logger = logging.getLogger(__name__)


def _post_with_retry(payload: dict) -> dict:
    """Post one OSV query page, retrying transient errors and rate limits."""
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.post(OSV_QUERY_URL, json=payload, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            if attempt == MAX_RETRIES - 1:
                raise
            time.sleep(0.5 * (2**attempt))
            continue

        if response.status_code in RETRYABLE_STATUS_CODES:
            if attempt == MAX_RETRIES - 1:
                response.raise_for_status()
            retry_after = response.headers.get("Retry-After")
            try:
                delay = float(retry_after) if retry_after else 0.5 * (2**attempt)
            except ValueError:
                delay = 0.5 * (2**attempt)
            time.sleep(max(0.0, min(delay, 10.0)))
            continue

        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("OSV returned an unexpected response shape")
        return result

    raise requests.RequestException("OSV query failed after retries")


def _cve_alias(vulnerability: Mapping) -> str:
    """Find the first CVE identifier in an OSV record's aliases."""
    aliases = vulnerability.get("aliases", [])
    if not isinstance(aliases, list):
        aliases = []
    identifiers = [vulnerability.get("id", ""), *aliases]
    for identifier in identifiers:
        if isinstance(identifier, str):
            match = CVE_PATTERN.search(identifier)
            if match:
                return match.group(0).upper()
    # Some OSV records have no CVE alias. Keep the required string field and
    # retain the finding using an empty value rather than inventing an ID.
    return ""


def lookup_vulnerabilities(dependencies: list[dict]) -> list[dict]:
    """Return OSV findings for dependency package/version pairs.

    Each valid dependency is queried separately using OSV's ``/v1/query``
    endpoint. Network, rate-limit, and malformed-record errors are logged and
    skipped so one problematic package does not stop the remaining lookups.
    """
    if not isinstance(dependencies, list):
        logger.warning("Expected dependencies as a list; no OSV queries were made.")
        return []

    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for dependency_index, dependency in enumerate(dependencies):
        if dependency_index:
            time.sleep(REQUEST_DELAY_SECONDS)
        if not isinstance(dependency, Mapping):
            logger.warning("Skipping malformed dependency entry: %r", dependency)
            continue

        ecosystem = dependency.get("ecosystem")
        name = dependency.get("name")
        version = dependency.get("version")
        if not all(isinstance(value, str) and value.strip() for value in (ecosystem, name, version)):
            logger.warning("Skipping dependency with missing ecosystem, name, or version: %r", dependency)
            continue

        payload = {
            "package": {"name": name.strip(), "ecosystem": ecosystem.strip()},
            "version": version.strip(),
        }
        page_token = None
        visited_tokens: set[str] = set()
        while True:
            if page_token:
                if page_token in visited_tokens:
                    logger.warning("OSV repeated a page token for %s %s; stopping pagination.", name, version)
                    break
                visited_tokens.add(page_token)
                payload["page_token"] = page_token
                time.sleep(REQUEST_DELAY_SECONDS)
            try:
                result = _post_with_retry(payload)
            except (requests.RequestException, ValueError) as exc:
                logger.warning("OSV query failed for %s %s (%s): %s", ecosystem, name, version, exc)
                break

            vulnerabilities = result.get("vulns", [])
            if not isinstance(vulnerabilities, list):
                logger.warning("OSV returned an invalid vulnerability list for %s %s.", name, version)
                break
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, Mapping):
                    logger.warning("Skipping malformed OSV vulnerability record for %s %s.", name, version)
                    continue
                osv_id = vulnerability.get("id")
                if not isinstance(osv_id, str) or not osv_id:
                    logger.warning("Skipping OSV record without an ID for %s %s.", name, version)
                    continue
                key = (name.strip().lower(), version.strip(), osv_id)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "package": name.strip(),
                    "version": version.strip(),
                    "cve_id": _cve_alias(vulnerability),
                    "osv_id": osv_id,
                    "summary": str(vulnerability.get("summary") or vulnerability.get("details") or ""),
                    # Preserve OSV's native severity evidence for consumers that
                    # do not have a matching CVE in their local enrichment data.
                    "severity": vulnerability.get("severity", []),
                })

            page_token = result.get("next_page_token")
            if not isinstance(page_token, str) or not page_token:
                break

    return findings
