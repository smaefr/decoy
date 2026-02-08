from __future__ import annotations

from pathlib import Path

import pytest

from decoy.config import Config
from decoy.store import EventStore


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    return str(tmp_path / "decoy.db")


@pytest.fixture
def store(db_path: str) -> EventStore:
    return EventStore(db_path)


@pytest.fixture
def config(db_path: str) -> Config:
    return Config(
        bind="127.0.0.1",
        http_port=0,
        ssh_port=0,
        db_path=db_path,
        rate_window_sec=60.0,
        rate_threshold=3,
        ssh_timeout_sec=1.0,
    )
