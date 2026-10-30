"""Dataset validation before team attack runs are analysed (P6 item 5)."""

from __future__ import annotations

import datetime as dt
import json
from ipaddress import IPv4Address, IPv4Network

import pytest

from afw.domain.events import HttpObservation, Provenance
from afw.ml.dataset_validation import Level, failed, validate
from afw.ml.datasets import DatasetManifest, Purpose, Role, SourceLabel

T0 = dt.datetime(2026, 10, 29, 10, 0, tzinfo=dt.UTC)
ZONE = IPv4Network("10.77.10.0/24")
ATK = IPv4Address("10.77.10.23")
USER = IPv4Address("10.77.20.170")


def o(i: int, ip: IPv4Address = ATK, **kw) -> HttpObservation:
    base = {
        "event_id": f"e{i}",
        "request_id": f"req{i:08d}",
        "app_id": "rental",
        "observed_at": T0 + dt.timedelta(seconds=10 + i),
        "client_ip": ip,
        "method": "GET",
        "path": "/",
        "route": "/",
        "status": 200,
        "app_joined": True,
        "reached_backend": True,
        "provenance": Provenance.AUTHENTICATED,
    }
    return HttpObservation(**(base | kw))


def manifest(**kw) -> DatasetManifest:
    base = {
        "dataset_id": "team-bf-1",
        "app_id": "rental",
        "purpose": Purpose.TEST,
        "scenario": "bf-login: bruteforce",
        "seed": 0,
        "start": T0,
        "end": T0 + dt.timedelta(minutes=10),
        "app_versions": ("1.0.0",),
        "sources": (
            SourceLabel(
                ip=ATK,
                role=Role.ATTACK,
                attack_type="bruteforce",
                start=T0,
                end=T0 + dt.timedelta(minutes=10),
            ),
            SourceLabel(ip=USER, role=Role.BENIGN),
        ),
        "n_observations": 4,
        "generator": "team-run by operator-a",
        "notes": json.dumps({"run_id": "run-1", "status": "ended"}),
    }
    return DatasetManifest(**(base | kw))


OBS = [o(0), o(1), o(2, USER), o(3, USER)]


def levels(findings):
    return {f.check: f.level for f in findings}


def test_clean_attack_run_passes():
    f = validate(manifest(), OBS, [], ZONE)
    assert not failed(f)
    assert all(x.level is Level.PASS for x in f), [x for x in f if x.level is not Level.PASS]


@pytest.mark.parametrize(
    ("change", "obs", "check"),
    [
        ({"n_observations": 5}, OBS, "count"),
        ({}, [*OBS[:3], o(3, USER, observed_at=T0 + dt.timedelta(hours=1))], "time_range"),
        ({}, [*OBS[:3], o(1, USER)], "request_ids_unique"),
        ({}, [*OBS[:3], o(3, IPv4Address("10.77.20.99"))], "observations_labelled"),
        ({"purpose": Purpose.TRAIN}, OBS, "attack_purpose"),
        ({"generator": "synthetic fixture"}, OBS, "not_synthetic"),
        (
            {"sources": (SourceLabel(ip=ATK, role=Role.ATTACK),)},
            [*OBS[:2], o(2), o(3)],
            "attack_type_set",
        ),
        (
            {
                "sources": (
                    SourceLabel(ip=USER, role=Role.ATTACK, attack_type="bruteforce"),
                    SourceLabel(ip=ATK, role=Role.BENIGN),
                )
            },
            OBS,
            "attackers_in_attack_zone",
        ),
        (
            {
                "sources": (
                    SourceLabel(ip=ATK, role=Role.ATTACK, attack_type="bruteforce"),
                    SourceLabel(ip=ATK, role=Role.BENIGN),
                    SourceLabel(ip=USER, role=Role.BENIGN),
                )
            },
            OBS,
            "roles_exclusive",
        ),
    ],
)
def test_defects_fail(change, obs, check):
    f = validate(manifest(**change), obs, [], ZONE)
    assert levels(f)[check] is Level.FAIL and failed(f)


def test_split_overlap_and_user_reuse():
    train = manifest(
        dataset_id="old-train",
        purpose=Purpose.TRAIN,
        sources=(SourceLabel(ip=USER, role=Role.BENIGN),),
        start=T0 - dt.timedelta(days=1),
        end=T0 - dt.timedelta(hours=23),
    )
    twin = manifest(dataset_id="team-bf-1-again")
    leak = manifest(dataset_id="team-bf-1-val", purpose=Purpose.VALIDATION)
    f = levels(validate(manifest(), OBS, [train, twin, leak], ZONE))
    assert f["no_cross_split_overlap"] is Level.FAIL
    assert f["no_same_split_overlap"] is Level.WARN
    assert f["benign_users_unseen"] is Level.WARN
    f = levels(validate(manifest(), OBS, [train], ZONE))
    assert f["no_cross_split_overlap"] is f["no_same_split_overlap"] is Level.PASS


def test_warnings_do_not_fail():
    weak = [*OBS[:3], o(3, USER, provenance=Provenance.UNVERIFIED)]
    m = manifest(
        sources=(
            SourceLabel(
                ip=ATK,
                role=Role.ATTACK,
                attack_type="bruteforce",
                start=T0 + dt.timedelta(seconds=11),
            ),
            SourceLabel(ip=USER, role=Role.BENIGN),
            SourceLabel(ip=IPv4Address("10.77.10.24"), role=Role.ATTACK, attack_type="scan"),
        ),
        notes=json.dumps({"run_id": "run-2", "status": "aborted", "abort_reason": "watchdog"}),
    )
    f = validate(m, weak, [], ZONE)
    lv = levels(f)
    assert not failed(f)
    assert lv["provenance"] is Level.WARN
    assert lv["labelled_sources_observed"] is Level.WARN  # 10.77.10.24 never reached the app
    assert lv["attacker_traffic_inside_label_window"] is Level.WARN  # o(0) before its start
    assert lv["run_aborted"] is Level.WARN
