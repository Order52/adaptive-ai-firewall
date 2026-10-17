from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from afw.config import Settings, load_lab_config

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


@pytest.fixture
def lab_cfg():
    return load_lab_config(ROOT / "config" / "lab.yaml")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(config=ROOT / "config" / "lab.yaml", data_dir=tmp_path / "var")


class FakeClock:
    def __init__(self, start: datetime = T0) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        from datetime import timedelta

        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()
