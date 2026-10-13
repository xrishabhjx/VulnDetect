"""Normalize common npm and Python dependency manifest entries."""

from __future__ import annotations

import json
import logging
import re
import tomllib
from collections.abc import Mapping

logger = logging.getLogger(__name__)

# Preserve the leading concrete version for common ranges such as ^1.2.3,
# ~1.2.3, >=1.2.3, and ==1.2.3. Complex ranges are intentionally simplified.
VERSION_RE = re.compile(r"(?:^|[<>=!~^\s])\s*[vV]?([0-9]+(?:\.[0-9]+){0,3}(?:[-+][0-9A-Za-z.-]+)?)")
PACKAGE_NAME_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?")


def _version_from_specifier(specifier: object) -> str | None:
    """Return the first concrete version from a simple range/specifier."""
    if isinstance(specifier, Mapping):
        specifier = specifier.get("version")
    if not isinstance(specifier, str):
        return None

    value = specifier.strip()
    if not value or value in {"*", "latest"}:
        return None
    # Local paths, workspace references, and VCS dependencies do not name a
    # concrete published version and are outside this lightweight parser.
    if value.startswith(("file:", "workspace:", "git+", "git://", "https://", "http://")):
        return None
    match = VERSION_RE.search(value)
    return match.group(1) if match else None


def _append_dependency(
    results: list[dict[str, str]], ecosystem: str, name: object, specifier: object
) -> None:
    if not isinstance(name, str):
        logger.warning("Skipping dependency with non-text package name: %r", name)
        return
    normalized_name = name.strip()
    # Extras are requirement syntax, not part of the canonical distribution name.
    normalized_name = normalized_name.split("[", 1)[0].strip()
    version = _version_from_specifier(specifier)
    if not normalized_name or not version:
        logger.warning("Skipping dependency that has no supported concrete version: %r", name)
        return
    results.append({"ecosystem": ecosystem, "name": normalized_name, "version": version})


def _parse_requirement_line(line: str) -> tuple[str, str] | None:
    """Parse a basic PEP 508 / requirements specifier line."""
    content = line.split(";", 1)[0].split("#", 1)[0].strip()
    if not content or content.startswith(("-", "http:", "https:", "git+")):
        return None
    name_match = PACKAGE_NAME_RE.match(content)
    if not name_match:
        return None

    name = name_match.group(1)
    remainder = content[name_match.end():].strip()
    # Only version constraints produce a normalized concrete version here.
    # Unpinned names and direct URL references have no version to report.
    version = _version_from_specifier(remainder)
    if not version:
        return None
    return name, version


def parse_dependencies(manifest_files: dict) -> list[dict]:
    """Parse dependency manifests returned by ``fetch_manifest_files``.

    Returns entries containing ``ecosystem`` (``npm`` or ``PyPI``), ``name``,
    and the first concrete version found in a simple version constraint.
    Unsupported version forms are logged and skipped.
    """
    if not isinstance(manifest_files, Mapping):
        logger.warning("Expected a mapping of manifest names to contents.")
        return []
    if "error" in manifest_files:
        logger.warning("Cannot parse repository manifests: %s", manifest_files["error"])
        return []

    results: list[dict[str, str]] = []

    package_json = manifest_files.get("package.json")
    if package_json is not None:
        try:
            package_data = json.loads(package_json) if isinstance(package_json, str) else package_json
            if not isinstance(package_data, Mapping):
                raise ValueError("package.json root must be an object")
            for section in ("dependencies", "devDependencies"):
                dependencies = package_data.get(section, {})
                if not isinstance(dependencies, Mapping):
                    logger.warning("Skipping invalid package.json %s section.", section)
                    continue
                for name, specifier in dependencies.items():
                    _append_dependency(results, "npm", name, specifier)
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            logger.warning("Skipping malformed package.json: %s", exc)

    requirements = manifest_files.get("requirements.txt")
    if requirements is not None:
        if not isinstance(requirements, str):
            logger.warning("Skipping requirements.txt because its content is not text.")
        else:
            for line_number, line in enumerate(requirements.splitlines(), start=1):
                parsed = _parse_requirement_line(line)
                if parsed is None:
                    if line.strip() and not line.lstrip().startswith("#"):
                        logger.warning("Skipping unsupported requirements.txt line %d: %s", line_number, line)
                    continue
                name, version = parsed
                _append_dependency(results, "PyPI", name, version)

    pyproject = manifest_files.get("pyproject.toml")
    if pyproject is not None:
        try:
            pyproject_data = tomllib.loads(pyproject) if isinstance(pyproject, str) else pyproject
            poetry_deps = pyproject_data.get("tool", {}).get("poetry", {}).get("dependencies", {})
            if isinstance(poetry_deps, Mapping):
                for name, specifier in poetry_deps.items():
                    if name.lower() != "python":
                        _append_dependency(results, "PyPI", name, specifier)

            project_deps = pyproject_data.get("project", {}).get("dependencies", [])
            if isinstance(project_deps, list):
                for requirement in project_deps:
                    if not isinstance(requirement, str):
                        logger.warning("Skipping non-text project dependency: %r", requirement)
                        continue
                    parsed = _parse_requirement_line(requirement)
                    if parsed is None:
                        logger.warning("Skipping unsupported pyproject dependency: %s", requirement)
                        continue
                    name, version = parsed
                    _append_dependency(results, "PyPI", name, version)
        except (AttributeError, tomllib.TOMLDecodeError, TypeError, ValueError) as exc:
            logger.warning("Skipping malformed pyproject.toml: %s", exc)

    # Keep the result stable and avoid duplicate entries when manifests repeat a package.
    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for dependency in results:
        key = (dependency["ecosystem"], dependency["name"].lower(), dependency["version"])
        if key not in seen:
            seen.add(key)
            unique.append(dependency)
    return unique
