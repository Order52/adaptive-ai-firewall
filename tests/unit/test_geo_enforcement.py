"""ADR-036: real-country enforcement, published tables, read-back and directional proof."""

from __future__ import annotations

import gzip
import hashlib
import json
from ipaddress import IPv4Address

import httpx
import pytest
from conftest import T0
from sqlalchemy import create_engine
from test_policy import intent

from afw.config import EgressTarget, OpnsenseConfig, ServiceConfig
from afw.domain.policy import CountryTarget, OperatingMode, PolicyKind, PolicyOrigin, PolicyState
from afw.enforcement.memory import MemoryBackend, MemoryProbe
from afw.enforcement.opnsense import OpnsenseBackend
from afw.geoip import GeoIpDatabase, install
from afw.persistence.repositories import SqlAuditLog, SqlPolicyRepository, SqlSettingsRepository
from afw.persistence.schema import metadata
from afw.policy.geo import GeoTables
from afw.policy.service import PolicyService
from afw.policy.validator import PolicyValidator
from afw.ports.enforcement import DesiredState

S = PolicyState
ROWS = [
    "1.0.0.0,1.0.0.255,AU",
    "1.1.1.0,1.1.1.255,AU",
    "1.0.1.0,1.0.3.255,CN",
    "8.8.8.0,8.8.8.255,US",
    "100.64.0.0,100.64.0.255,KP",  # shared address space: never published
    "175.45.176.0,175.45.176.255,KP",
]


@pytest.fixture
def db(tmp_path):
    src = tmp_path / "dl.csv.gz"
    with gzip.open(src, "wt") as f:
        f.write("\n".join(sorted(ROWS, key=lambda r: IPv4Address(r.split(",")[0]))) + "\n")
    install(src, tmp_path / "geo", "2026-10", "u", T0, min_ranges=1)
    return GeoIpDatabase.load(tmp_path / "geo")


@pytest.fixture
def cfg(lab_cfg):
    g = lab_cfg.geo_enforcement.model_copy(
        update={
            "enabled": True,
            "max_networks": 10,
            "egress_source": IPv4Address("10.77.20.10"),
            "egress_targets": {
                "au": EgressTarget(address=IPv4Address("1.1.1.1")),
                "us": EgressTarget(address=IPv4Address("8.8.8.8")),
            },
        }
    )
    return lab_cfg.model_copy(update={"geo_enforcement": g})


@pytest.fixture
def geo(cfg, db):
    return GeoTables(cfg.geo_enforcement, lambda: db)


@pytest.fixture
def svc(cfg, geo, clock, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/p.sqlite3")
    metadata.create_all(engine)
    backend = MemoryBackend()
    probe = MemoryProbe(backend, egress={"au": "AU", "us": "US"})
    service = PolicyService(
        repo=SqlPolicyRepository(engine),
        validator=PolicyValidator(cfg, geo),
        backends=[backend],
        settings=SqlSettingsRepository(engine, OperatingMode.MONITOR),
        audit=SqlAuditLog(engine),
        probe=probe,
        clock=clock,
        geo=geo,
    )
    return service, backend, probe


def country(cc, direction="outbound", origin=PolicyOrigin.MCP):
    t = CountryTarget(country_code=cc, direction=direction, simulated=False)
    return intent(kind=PolicyKind.GEO_BLOCK, target=t, origin=origin, duration=600)


# ------------------------------------------------------------------ tables
def test_published_list_is_global_only_sorted_and_hash_addressed(geo):
    lst = geo.publish("outbound", frozenset({"AU", "KP"}))
    assert lst.networks == ("1.0.0.0/24", "1.1.1.0/24", "175.45.176.0/24")  # no 100.64/10
    text = lst.text("outbound")
    head, body = text.split("\n", 1)
    assert head.endswith(f"sha256={hashlib.sha256(body.encode()).hexdigest()}")
    assert "countries=AU,KP count=3" in head
    assert (
        geo.publish("outbound", frozenset())
        .text("outbound")
        .startswith("# afw-geo direction=outbound countries=- count=0 ")
    )


def test_a_country_is_present_only_when_every_network_is_in_the_table(geo):
    full = frozenset({"1.0.0.0/24", "1.1.1.0/24", "8.8.8.0/24"})
    assert geo.present(full, frozenset({"AU", "US", "CN"})) == {"AU", "US"}
    assert geo.present(full - {"1.1.1.0/24"}, frozenset({"AU"})) == frozenset()


def test_tables_above_the_network_budget_are_refused(geo):
    geo.cfg = geo.cfg.model_copy(update={"max_networks": 2})
    with pytest.raises(ValueError, match="exceed"):
        geo.publish("inbound", frozenset({"AU", "CN"}))
    assert geo.published["inbound"].countries == ()  # previous list kept


# --------------------------------------------------------------- validator
def test_real_country_policy_is_accepted_with_directional_notes(cfg, geo, clock):
    v = PolicyValidator(cfg, geo).validate(country("AU", "both"), OperatingMode.AUTO, 0, clock())
    assert v.ok, v.errors
    assert not v.auto_eligible
    assert any("REAL geography: 2 networks of AU" in n for n in v.notes)
    assert any(n.startswith("inbound: verified by table read-back only") for n in v.notes)


@pytest.mark.parametrize(
    "mutate,needle",
    [
        (lambda c, g, i: (c, g, country("AU", origin=PolicyOrigin.AI)), "operator decisions"),
        (lambda c, g, i: (c, g, country("FR")), "not a country"),
        (lambda c, g, i: (c, None, i), "not enabled"),
        (lambda c, g, i: (_disabled(c), g, i), "not enabled"),
        (lambda c, g, i: (c, _no_db(g), i), "no GeoIP database"),
        (lambda c, g, i: (_budget(c, 1), _budget_geo(g, 1), i), "above the per-direction"),
    ],
)
def test_real_country_policy_refusals(cfg, geo, clock, mutate, needle):
    c, g, i = mutate(cfg, geo, country("AU"))
    v = PolicyValidator(c, g).validate(i, OperatingMode.ASSISTED, 0, clock())
    assert not v.ok and any(needle in e for e in v.errors), v.errors


def test_a_stale_database_refuses_new_country_policies(cfg, geo, clock):
    clock.advance(60 * 86400)
    v = PolicyValidator(cfg, geo).validate(country("AU"), OperatingMode.ASSISTED, 0, clock())
    assert not v.ok and any("stale" in e for e in v.errors)


def _disabled(c):
    return c.model_copy(
        update={"geo_enforcement": c.geo_enforcement.model_copy(update={"enabled": False})}
    )


def _no_db(g):
    return GeoTables(g.cfg, lambda: None)


def _budget(c, n):
    return c.model_copy(
        update={"geo_enforcement": c.geo_enforcement.model_copy(update={"max_networks": n})}
    )


def _budget_geo(g, n):
    return GeoTables(g.cfg.model_copy(update={"max_networks": n}), g.db)


# ----------------------------------------------------------------- service
def test_outbound_policy_is_enforced_only_after_read_back_and_egress_proof(svc):
    service, backend, _ = svc
    p = service.submit(country("AU"))
    assert p.state is S.ENFORCED, p.history[-2:]
    assert backend.state.geo_outbound == {"AU"} and not backend.state.geo_inbound
    assert p.verification["readback"] is True
    assert p.verification["traffic_outbound"] == "blocked: au; control us connected"
    service.revoke(p.policy_id, "test", "done")
    assert not backend.state.geo_outbound
    assert service.repo.get(p.policy_id).state is S.ROLLED_BACK


def test_inbound_policy_stays_unverified_because_no_real_traffic_reaches_the_lab(svc, clock):
    service, backend, _ = svc
    p = service.submit(country("CN", "inbound"))
    assert p.state is S.APPLIED_UNVERIFIED
    assert backend.state.geo_inbound == {"CN"}
    assert p.verification["readback"] is True
    assert p.verification["traffic_inbound"].startswith("n/a")
    clock.advance(60)
    service.reconcile()
    assert service.repo.get(p.policy_id).state is S.APPLIED_UNVERIFIED


def test_both_directions_are_not_enforced_on_outbound_proof_alone(svc):
    service, _, _ = svc
    p = service.submit(country("AU", "both"))
    assert p.state is S.APPLIED_UNVERIFIED
    assert p.verification["traffic_outbound"].startswith("blocked")


def test_a_failing_control_target_is_an_outage_not_proof(svc, clock):
    service, _, probe = svc
    probe.internet_up = False
    p = service.submit(country("AU"))
    assert p.state is S.APPLIED_UNVERIFIED
    assert "outage, not proof" in p.verification["traffic_outbound"]
    probe.internet_up = True
    clock.advance(10)
    service.reconcile()  # within the probe interval: not re-probed yet
    assert service.repo.get(p.policy_id).state is S.APPLIED_UNVERIFIED
    clock.advance(30)
    service.reconcile()
    assert service.repo.get(p.policy_id).state is S.ENFORCED


def test_a_country_without_a_probe_target_is_never_claimed_enforced(svc):
    service, _, _ = svc
    p = service.submit(country("CN"))
    assert p.state is S.APPLIED_UNVERIFIED
    assert p.verification["traffic_outbound"] == "unverified: no egress probe target in CN"


def test_the_service_publishes_what_fw01_pulls_and_withdraws_it(svc, geo):
    service, _, _ = svc
    p = service.submit(country("AU"))
    assert geo.published["outbound"].networks == ("1.0.0.0/24", "1.1.1.0/24")
    assert geo.published["inbound"].networks == ()
    service.revoke(p.policy_id, "test", "done")
    assert geo.published["outbound"].networks == ()


def test_a_policy_over_the_network_budget_fails_without_disturbing_others(svc, geo):
    service, _, _ = svc
    first = service.submit(country("AU"))
    geo.cfg = geo.cfg.model_copy(update={"max_networks": 2})
    second = service.submit(country("KP"))  # AU + KP = 3 networks > 2
    assert second.state is S.FAILED and "exceed" in second.history[-1].note
    assert service.repo.get(first.policy_id).state is S.ENFORCED
    assert geo.published["outbound"].countries == ("AU",)
    service.reconcile()
    assert service.repo.get(second.policy_id).state is S.FAILED  # no retry loop


def test_a_table_that_never_fills_is_not_enforced(svc):
    service, backend, _ = svc
    backend.drop_on_apply = True  # published, but the firewall never loads it
    p = service.submit(country("AU"))
    assert p.state is S.APPLIED_UNVERIFIED
    assert "readback" not in p.verification


# ------------------------------------------------------------ OPNsense read-back
def _opnsense(tmp_path, handler, geo):
    for n in ("k", "s"):
        (tmp_path / n).write_text("x")
    cfg = OpnsenseConfig(
        base_url="https://fw.test", key_file=tmp_path / "k", secret_file=tmp_path / "s"
    )
    svc = ServiceConfig(
        name="rental_https", app_id="rental", address=IPv4Address("10.77.30.10"), port=443
    )
    b = OpnsenseBackend(cfg, svc, geo)
    b.client = httpx.Client(base_url="https://fw.test/api", transport=httpx.MockTransport(handler))
    return b


def test_backend_publishes_then_reads_the_live_tables_back_in_pages(tmp_path, geo, monkeypatch):
    import afw.enforcement.opnsense as mod

    monkeypatch.setattr(mod, "PAGE", 1)
    tables = {"AFW_GEO_OUT": ["1.0.0.0/24", "1.1.1.0/24"], "AFW_GEO_IN": []}
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        path = req.url.path.removeprefix("/api")
        calls.append(path)
        if path.startswith("/firewall/alias_util/list/AFW_GEO"):
            body = json.loads(req.content)
            rows = tables[path.rsplit("/", 1)[1]]
            page = rows[body["current"] - 1 : body["current"]]
            return httpx.Response(200, json={"rows": [{"ip": r} for r in page], "total": len(rows)})
        if path.startswith("/firewall/alias_util/list/"):
            return httpx.Response(200, json={"rows": [], "total": 0})
        return httpx.Response(200, json={"status": "done"})

    b = _opnsense(tmp_path, handler, geo)
    geo.publish("outbound", frozenset({"AU"}))  # the policy service's job
    assert b.reconcile(DesiredState(geo_outbound=frozenset({"AU"}))).ok
    obs = b.observe()
    assert obs.geo_outbound == {"AU"} and obs.geo_inbound == frozenset()
    assert calls.count("/firewall/alias_util/list/AFW_GEO_OUT") == 2  # two pages of one

    # inbound was read once, found empty, and is not listed again while nothing is published
    calls.clear()
    b.observe()
    assert "/firewall/alias_util/list/AFW_GEO_IN" not in calls

    # withdrawn but not yet pulled by FW01: a watched country is still reported present,
    # so the policy is not declared removed before the firewall has actually dropped it
    geo.publish("outbound", frozenset())
    b.reconcile(DesiredState(geo_watch=frozenset({"AU"})))
    assert b.observe().geo_outbound == {"AU"}
    tables["AFW_GEO_OUT"] = ["1.0.0.0/24"]  # FW01 synced (partially, here): gone
    assert b.observe().geo_outbound == frozenset()


def test_backend_without_geo_refuses_country_desired_state(tmp_path):
    b = _opnsense(tmp_path, lambda r: httpx.Response(200, json={"rows": [], "total": 0}), None)
    rep = b.reconcile(DesiredState(geo_inbound=frozenset({"CN"})))
    assert not rep.ok and "not configured" in (rep.error or "")
