"""Decision explanations must survive the detections-table retention purge.

Occlusion attributions are snapshotted onto the assessment at decision time, so
`explain` stays self-contained even after old detections are pruned.
"""

from __future__ import annotations

from datetime import timedelta
from ipaddress import IPv4Address

import pytest
from conftest import T0, FakeClock
from fixtures.synthetic import traffic

from afw.container import build_container
from afw.domain.policy import OperatingMode, PolicyKind
from afw.ml.datasets import DatasetManifest, Purpose, Role, SourceLabel
from afw.services.explain import explain_policy

BENIGN = [f"10.77.20.{i}" for i in range(11, 21)]
ATTACKER = "10.77.10.23"


def _manifest(ds_id, purpose, obs, benign, attack=None):
    attack = attack or {}
    return DatasetManifest(
        dataset_id=ds_id,
        app_id="rental",
        purpose=purpose,
        scenario="synthetic-explain",
        seed=1,
        start=obs[0].observed_at,
        end=obs[-1].observed_at,
        app_versions=("1.0.0",),
        sources=tuple(SourceLabel(ip=IPv4Address(i), role=Role.BENIGN) for i in benign)
        + tuple(
            SourceLabel(ip=IPv4Address(k), role=Role.ATTACK, attack_type=v)
            for k, v in attack.items()
        ),
        generator="tests/fixtures/synthetic.py",
    )


@pytest.fixture
def blocked(settings):
    c = build_container(settings, simulated=True)
    clock = FakeClock(T0 + timedelta(days=1))
    c.learning.clock = clock
    c.policy_service.clock = clock
    c.controller.clock = clock
    tr = traffic(1, T0, 1800, BENIGN)
    va = traffic(2, T0 + timedelta(hours=2), 900, BENIGN, attack={ATTACKER: "bruteforce"})
    c.datasets.write(_manifest("syn-train", Purpose.TRAIN, tr, BENIGN), tr)
    c.datasets.write(
        _manifest("syn-val", Purpose.VALIDATION, va, BENIGN, {ATTACKER: "bruteforce"}), va
    )
    res = c.learning.bootstrap("rental", ["syn-train"], ["syn-val"])
    c.learning.promote("rental", res.profile.version, "reviewer", "baseline")
    c.controller.reload()
    c.settings_repo.set_mode(OperatingMode.AUTO, "test")
    c.policy_service.reconcile()
    live = traffic(9, clock(), 300, BENIGN, attack={ATTACKER: "bruteforce+scrape"})
    t = clock()
    for o in live:
        while o.observed_at > t:
            c.controller.tick(t)
            t += timedelta(seconds=1)
            clock.now = t
        c.controller.ingest_observations([o])
    c.controller.tick(t)
    block = next(p for p in c.policies_repo.recent(200) if p.kind is PolicyKind.SOURCE_BLOCK)
    return c, block


def test_assessment_snapshots_detections(blocked):
    c, block = blocked
    ra = c.analysis.get_assessment(block.intent.risk_assessment_id)
    assert ra is not None
    # The full detector outputs are stored on the assessment, with attributions.
    assert ra.detections, "detections must be snapshotted onto the assessment"
    assert {d.detector.value for d in ra.detections} >= {"robust_stats", "isolation_forest"}
    assert any(d.contributions for d in ra.detections if d.is_anomalous)


def test_explain_survives_detection_purge(blocked):
    c, block = blocked
    # Purge every detection row (simulate 7-day retention having run).
    c.events.purge_before(T0 + timedelta(days=3650))
    assert c.analysis.recent_detections(5000) == []

    x = explain_policy(block, c.analysis, c.events)
    cf = x["contributing_features"]
    assert cf, "explanation lost its attributions after the purge"
    detectors = {d["detector"] for d in cf}
    assert "isolation_forest" in detectors
    assert any(d["contributions"] for d in cf), "occlusion attributions must still be present"
