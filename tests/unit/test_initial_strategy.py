"""ADR-045: the start-up strategy comes from config, and the lab ships `statistical`."""

from __future__ import annotations

import pytest

from afw.config import LabConfig
from afw.ml.inference import InferenceEngine, Strategy


def test_lab_config_starts_statistical(lab_cfg: LabConfig) -> None:
    assert lab_cfg.initial_strategy == "statistical"


def test_every_configured_value_is_a_strategy(lab_cfg: LabConfig) -> None:
    for value in ("static", "statistical", "ml"):
        engine = InferenceEngine()
        engine.strategy = Strategy(
            lab_cfg.model_copy(update={"initial_strategy": value}).initial_strategy
        )
        assert engine.strategy.value == value


def test_default_without_the_key_is_ml(lab_cfg: LabConfig) -> None:
    raw = lab_cfg.model_dump(mode="json")
    raw.pop("initial_strategy")
    assert LabConfig.model_validate(raw).initial_strategy == "ml"


def test_unknown_value_is_refused(lab_cfg: LabConfig) -> None:
    raw = lab_cfg.model_dump(mode="json") | {"initial_strategy": "magic"}
    with pytest.raises(ValueError):
        LabConfig.model_validate(raw)


def test_controller_applies_it(lab_cfg: LabConfig) -> None:
    from afw.ml.inference import DetectorKind

    engine = InferenceEngine()
    engine.strategy = Strategy(lab_cfg.initial_strategy)
    assert engine.active_kinds() == [DetectorKind.ROBUST_STATS]
