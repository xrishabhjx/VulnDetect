"""Keep pytest's temporary files inside this project on Windows hosts."""

from pathlib import Path


def pytest_configure(config):
    """Use a project-local base temp folder instead of the system Temp path."""
    project_root = Path(__file__).resolve().parent
    temp_root = project_root / ".pytest_tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    config.option.basetemp = str(temp_root)
