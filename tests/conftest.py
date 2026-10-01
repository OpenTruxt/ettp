from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolate_default_evidence_path(tmp_path, monkeypatch) -> None:
    """Keep PolicyEngine's production default durable while isolating test files."""
    monkeypatch.setenv("ETTP_EVIDENCE_PATH", str(tmp_path / ".ettp" / "events.jsonl"))
