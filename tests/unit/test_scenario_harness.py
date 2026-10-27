"""M6 harness: registry safety, ground-truth journal, kill switch, evaluation hygiene."""

from __future__ import annotations

import copy
from datetime import timedelta
from ipaddress import IPv4Address

import pytest
import yaml
from conftest import ROOT, T0

from afw.lab.scenarios import (
    Registry,
    RunJournal,
    RunStatus,
    load_registry,
    manifest_for,
)
from afw.ml.datasets import DatasetManifest, SourceLabel
from afw.ml.experiments import ArmReport, ExperimentReport
from afw.ml.run_evaluation import aggregate

RAW = yaml.safe_load((ROOT / "config" / "scenarios.yaml").read_text())


def test_shipped_registry_is_valid_and_safe(lab_cfg):
    reg = load_registry(ROOT / "config" / "scenarios.yaml", lab_cfg)
    assert len(reg.scenarios) >= 4
    for s in reg.scenarios:
        assert all(str(ip).startswith("10.77.10.") for ip in s.attackers)
        assert all(not str(t.ip).startswith(("10.77.50.", "10.77.60.")) for t in s.targets)


@pytest.mark.parametrize("ip", ["10.77.50.10", "10.77.60.10", "8.8.8.8", "192.168.1.1"])
def test_denied_or_external_targets_are_refused(ip):
    raw = copy.deepcopy(RAW)
    raw["allowed_targets"].append({"ip": ip, "port": 443})
    with pytest.raises(ValueError, match="outside the lab or in a denied network"):
        Registry.model_validate(raw)


def test_scenario_target_must_be_on_the_allowlist():
    raw = copy.deepcopy(RAW)
    raw["scenarios"][0]["targets"] = [{"ip": "10.77.40.10", "port": 8000}]  # APP01 direct
    with pytest.raises(ValueError, match="not on the allowlist"):
        Registry.model_validate(raw)


@pytest.mark.parametrize("ip", ["10.77.20.10", "10.77.10.250", "10.77.10.1"])
def test_attackers_must_be_attack_zone_clients(tmp_path, lab_cfg, ip):
    raw = copy.deepcopy(RAW)
    raw["scenarios"][0]["attackers"] = [ip]
    p = tmp_path / "s.yaml"
    p.write_text(yaml.safe_dump(raw))
    with pytest.raises(ValueError, match="not an ATTACK-zone client"):
        load_registry(p, lab_cfg)


def test_max_duration_is_capped():
    raw = copy.deepcopy(RAW)
    raw["scenarios"][0]["max_duration_s"] = 7200
    with pytest.raises(ValueError):
        Registry.model_validate(raw)


@pytest.fixture
def reg(lab_cfg):
    return load_registry(ROOT / "config" / "scenarios.yaml", lab_cfg)


def test_journal_lifecycle_and_single_active_run(tmp_path, reg):
    j = RunJournal(tmp_path)
    spec = reg.get("web-bruteforce-login")
    with pytest.raises(ValueError, match="operator"):
        j.begin(spec, " ", T0)
    r = j.begin(spec, "team-member-a", T0)
    with pytest.raises(ValueError, match="still running"):
        j.begin(spec, "team-member-b", T0)
    j.mark(r.run_id, "phase 2: wordlist B", T0 + timedelta(seconds=60))
    done = j.end(r.run_id, T0 + timedelta(seconds=300))
    assert done.status is RunStatus.ENDED and j.active() is None
    with pytest.raises(ValueError, match="ended"):
        j.mark(r.run_id, "late", T0 + timedelta(seconds=400))
    m = manifest_for(done, spec, [IPv4Address("10.77.20.10")])
    labels = {s["ip"]: s for s in m["sources"]}
    assert labels["10.77.10.10"]["role"] == "attack"
    assert labels["10.77.10.10"]["start"] == T0.isoformat()
    assert labels["10.77.20.10"]["role"] == "benign"
    assert "team-member-a" in m["generator"]
    DatasetManifest.model_validate(  # what `afw dataset capture` will build from it
        {
            **{k: m[k] for k in ("app_id", "scenario", "seed", "generator", "notes")},
            "dataset_id": "x",
            "purpose": "test",
            "start": m["start"],
            "end": m["end"],
            "app_versions": (),
            "sources": [SourceLabel.model_validate(s) for s in m["sources"]],
        }
    )


def test_kill_switch_stops_attack_host_before_recording(tmp_path, reg):
    j = RunJournal(tmp_path)
    r = j.begin(reg.get("net-portscan"), "team-member-a", T0)
    calls = []
    out = j.abort(
        r.run_id,
        "target misbehaving",
        T0 + timedelta(seconds=5),
        lambda: calls.append("stop") or ["ATK01 stopped"],
    )
    assert calls == ["stop"]
    assert out.status is RunStatus.ABORTED and out.kill_result == ["ATK01 stopped"]
    assert j.active() is None


def test_watchdog_aborts_only_past_max_duration(tmp_path, reg):
    j = RunJournal(tmp_path)
    spec = reg.get("net-portscan")
    j.begin(spec, "team-member-a", T0)
    calls = []
    kill = lambda: calls.append(1) or ["ATK01 stopped"]
    assert j.watchdog(reg, T0 + timedelta(seconds=spec.max_duration_s), kill) is None
    r = j.watchdog(reg, T0 + timedelta(seconds=spec.max_duration_s + 1), kill)
    assert r is not None and r.status is RunStatus.ABORTED and "watchdog" in r.abort_reason
    assert calls == [1]


def _report(ds: str, recall: float, contained: int) -> ExperimentReport:
    arm = ArmReport(
        arm="M2",
        strategy="ml",
        recall=recall,
        fpr=0.01,
        attack_sources=1,
        attack_sources_contained=contained,
        median_detection_latency_s=20.0,
        legit_request_success=0.99,
    )
    return ExperimentReport(
        dataset_id=ds,
        scenario="s",
        purpose="test",
        app_id="rental",
        profile_version=1,
        model_versions={},
        fp_budget=0.01,
        window_length_s=30,
        window_hop_s=5,
        n_observations=1,
        duration_s=1.0,
        waf_inline_blocked_requests=0,
        waf_inline_contained_attack_sources=0,
        arms=[arm],
    )


def _manifest(ds: str, generator: str = "team-run by x") -> DatasetManifest:
    return DatasetManifest(
        dataset_id=ds,
        app_id="rental",
        purpose="test",
        scenario="s",
        seed=0,
        start=T0,
        end=T0,
        app_versions=(),
        sources=(),
        generator=generator,
    )


def test_evaluation_refuses_synthetic_and_reports_cis_over_runs():
    reps = [_report(f"r{i}", r, c) for i, (r, c) in enumerate([(0.8, 1), (0.6, 1), (1.0, 0)])]
    with pytest.raises(ValueError, match="synthetic"):
        aggregate(reps, [_manifest("r0", "tests/fixtures/synthetic.py")])
    res = aggregate(reps, [_manifest(r.dataset_id) for r in reps])
    rec = res["arms"]["M2"]["recall"]
    assert rec["n_runs"] == 3 and rec["mean"] == 0.8
    lo, hi = rec["ci95_over_runs"]
    assert 0.6 <= lo <= 0.8 <= hi <= 1.0
    assert res["arms"]["M2"]["containment"]["mean"] == round(2 / 3, 4)
    two = aggregate(reps[:2], [_manifest(r.dataset_id) for r in reps[:2]])
    assert two["arms"]["M2"]["recall"]["ci95_over_runs"] is None  # too few runs for a CI
    demo = aggregate(reps, [_manifest("r0", "synthetic")], allow_synthetic=True)
    assert demo["label"].startswith("SYNTHETIC")
