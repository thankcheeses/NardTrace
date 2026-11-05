import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _offline_env(tmp_path, monkeypatch):
    """Every test runs offline with an isolated data directory and database."""
    monkeypatch.setenv("NARDTRACE_OFFLINE", "1")
    monkeypatch.setenv("NARDTRACE_DATA_DIR", str(tmp_path / "data"))
    for k in ("ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "GOOGLE_SAFE_BROWSING_API_KEY", "IPINFO_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    yield


@pytest.fixture
def fixture_bytes():
    def _load(name: str) -> bytes:
        return (FIXTURES / name).read_bytes()
    return _load
