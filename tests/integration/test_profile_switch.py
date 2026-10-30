"""Profile promotion and rollback are crash-consistent (directive item 8, ADR-040).

A trusted profile and its active models change together or not at all: an interrupted
switch must never leave no trusted profile, or a trusted profile with only some of its
detectors active (the controller loads only models of the trusted version)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from conftest import T0, FakeClock
from fixtures.synthetic import traffic
from sqlalchemy import event
from test_closed_loop import BENIGN, manifest

from afw.container import build_container
from afw.domain.detection import DetectorKind
from afw.ml.datasets import Purpose


@pytest.fixture
def two_versions(settings):
    c = build_container(settings, simulated=True)
    c.learning.clock = FakeClock(T0 + timedelta(days=1))
    tr = traffic(1, T0, 1800, BENIGN)
    va = traffic(2, T0 + timedelta(hours=2), 900, BENIGN, attack={"10.77.10.23": "bruteforce"})
    c.datasets.write(manifest("syn-train", Purpose.TRAIN, tr, BENIGN), tr)
    c.datasets.write(manifest("syn-val", Purpose.VALIDATION, va, BENIGN, ["10.77.10.23"]), va)
    first = c.learning.bootstrap("rental", ["syn-train"], ["syn-val"], seed=1)
    c.learning.promote("rental", first.profile.version, "reviewer", "v1")
    second = c.learning.bootstrap("rental", ["syn-train"], ["syn-val"], seed=2)
    return c, first.profile.version, second.profile.version


def _state(c):
    loaded = c.learning.load_active("rental")
    if loaded is None:
        return None, set()
    prof, models = loaded
    return prof.version, {m.record.detector for m in models}


def _fail_nth_write(c, n):
    seen = [0]

    def before(conn, cursor, statement, params, context, executemany):
        s = statement.lstrip().upper()
        if s.startswith(("UPDATE MODELS", "UPDATE PROFILES", "INSERT INTO MODELS")):
            seen[0] += 1
            if seen[0] == n:
                raise RuntimeError("injected crash")

    engine = c.learning.models.engine
    event.listen(engine, "before_cursor_execute", before)
    return lambda: event.remove(engine, "before_cursor_execute", before)


ALL = {DetectorKind.ROBUST_STATS, DetectorKind.ISOLATION_FOREST, DetectorKind.HALF_SPACE_TREES}


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5])
def test_interrupted_promotion_keeps_the_old_profile_complete(two_versions, n):
    c, v1, v2 = two_versions
    assert _state(c) == (v1, ALL)
    undo = _fail_nth_write(c, n)
    with pytest.raises(Exception, match="injected crash"):
        c.learning.promote("rental", v2, "reviewer", "v2")
    undo()
    assert _state(c) == (v1, ALL)
    c.learning.promote("rental", v2, "reviewer", "retry")
    assert _state(c) == (v2, ALL)


@pytest.mark.parametrize("n", [1, 3])
def test_interrupted_rollback_keeps_the_current_profile_complete(two_versions, n):
    c, v1, v2 = two_versions
    c.learning.promote("rental", v2, "reviewer", "v2")
    undo = _fail_nth_write(c, n)
    with pytest.raises(Exception, match="injected crash"):
        c.learning.rollback("rental", v1, "reviewer", "back")
    undo()
    assert _state(c) == (v2, ALL)


def _corrupt(c, version, detector=DetectorKind.ISOLATION_FOREST):
    from pathlib import Path

    rec = next(
        m
        for m in c.learning.models.list("rental")
        if m.profile_version == version and m.detector is detector
    )
    p = Path(rec.artifact_path)
    p.write_bytes(p.read_bytes()[:-64] + b"\0" * 64)


def test_switch_to_a_version_with_a_corrupt_artifact_is_refused(two_versions):
    """Found 2026-10-28 with real artifacts: a rollback trusted a profile whose model
    failed its integrity check, so no controller could load the trusted state."""
    c, v1, v2 = two_versions
    c.learning.promote("rental", v2, "reviewer", "v2")
    _corrupt(c, v1)
    with pytest.raises(ValueError, match="artifact rejected"):
        c.learning.rollback("rental", v1, "reviewer", "back")
    assert _state(c) == (v2, ALL)


def test_controller_survives_a_corrupt_active_artifact(two_versions):
    """No crash loop, no stale or partial model set: no behavioural models, a visible
    error, and degraded evidence (automation pauses) until a human acts."""
    c, v1, _ = two_versions
    assert c.controller.reload() and c.controller.inference.models
    _corrupt(c, v1)
    assert c.controller.reload() is False
    assert c.controller.inference.models == {} and c.controller.inference.profile is None
    assert c.controller.model_error and "integrity" in c.controller.model_error
    assert c.controller.degraded()
