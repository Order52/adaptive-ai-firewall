from __future__ import annotations

from ipaddress import IPv4Address

import pytest
from sqlalchemy import create_engine

from afw.domain.policy import (
    ContractTarget,
    CountryTarget,
    InvalidTransition,
    OperatingMode,
    PolicyIntent,
    PolicyKind,
    PolicyOrigin,
    PolicyState,
    RateProfile,
    SourceTarget,
    check_transition,
)
from afw.enforcement.memory import MemoryBackend, MemoryProbe
from afw.persistence.repositories import (
    SqlAuditLog,
    SqlPolicyRepository,
    SqlSettingsRepository,
)
from afw.persistence.schema import metadata
from afw.policy.service import PolicyService
from afw.policy.validator import PolicyValidator

S = PolicyState
ATTACKER = "10.77.10.23"


def intent(
    ip=ATTACKER, kind=PolicyKind.SOURCE_BLOCK, duration=120, origin=PolicyOrigin.AI, level=0, **kw
):
    return PolicyIntent(
        kind=kind,
        app_id="rental",
        service="rental_https",
        target=kw.pop("target", SourceTarget(source_ip=IPv4Address(ip))),
        duration_s=duration,
        origin=origin,
        requested_by="test",
        escalation_level=level,
        **kw,
    )


@pytest.fixture
def svc(lab_cfg, clock, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/p.sqlite3")
    metadata.create_all(engine)
    backend = MemoryBackend()
    settings = SqlSettingsRepository(engine, OperatingMode.AUTO)
    service = PolicyService(
        repo=SqlPolicyRepository(engine),
        validator=PolicyValidator(lab_cfg),
        backends=[backend],
        settings=settings,
        audit=SqlAuditLog(engine),
        probe=MemoryProbe(backend),
        clock=clock,
    )
    return service, backend, settings


# ---------------------------------------------------------------- validator
@pytest.mark.parametrize(
    "ip,needle",
    [
        ("10.77.50.10", "protected"),  # management
        ("10.77.30.10", "protected"),  # WAF
        ("10.77.20.250", "protected"),  # verification probe
        ("8.8.8.8", "outside the configured client zones"),
        ("10.77.10.1", "protected"),  # firewall interface
    ],
)
def test_validator_rejects_unsafe_targets(lab_cfg, clock, ip, needle):
    v = PolicyValidator(lab_cfg).validate(intent(ip), OperatingMode.AUTO, 0, clock())
    assert not v.ok and any(needle in e for e in v.errors)


def test_validator_bounds_duration_and_auto(lab_cfg, clock):
    val = PolicyValidator(lab_cfg)
    assert not val.validate(intent(duration=5), OperatingMode.AUTO, 0, clock()).ok
    long = val.validate(intent(duration=1800), OperatingMode.AUTO, 0, clock())
    assert long.ok and not long.auto_eligible  # needs approval
    ok = val.validate(intent(), OperatingMode.AUTO, 0, clock())
    assert ok.ok and ok.auto_eligible
    degraded = val.validate(intent(), OperatingMode.AUTO, 0, clock(), degraded_telemetry=True)
    assert degraded.ok and not degraded.auto_eligible


def test_contract_must_match_owner_declaration(lab_cfg, clock):
    val = PolicyValidator(lab_cfg)
    good = ContractTarget(
        route="/booking",
        allowed_methods=("POST",),
        allowed_content_types=("application/json",),
        max_body_bytes=4096,
        revision=1,
    )
    bad = good.model_copy(update={"allowed_methods": ("POST", "DELETE")})
    mk = lambda t: intent(kind=PolicyKind.HTTP_CONTRACT, duration=None, target=t)
    assert val.validate(mk(good), OperatingMode.ASSISTED, 0, clock()).ok
    assert not val.validate(mk(bad), OperatingMode.ASSISTED, 0, clock()).ok


def test_geo_requires_real_geoip_unless_simulated(lab_cfg, clock):
    val = PolicyValidator(lab_cfg)
    real = CountryTarget(country_code="CN", direction="inbound", simulated=False)
    sim = real.model_copy(update={"simulated": True})
    mk = lambda t: intent(kind=PolicyKind.GEO_BLOCK, target=t, origin=PolicyOrigin.MCP)
    assert not val.validate(mk(real), OperatingMode.ASSISTED, 0, clock()).ok
    assert val.validate(mk(sim), OperatingMode.ASSISTED, 0, clock()).ok


def test_state_machine_rejects_illegal_transition():
    check_transition(S.APPLYING, S.APPLIED_UNVERIFIED)
    with pytest.raises(InvalidTransition):
        check_transition(S.EXPIRED, S.ENFORCED)


# ---------------------------------------------------------------- lifecycle
def test_auto_block_is_enforced_verified_and_expires(svc, clock):
    service, backend, _ = svc
    p = service.submit(intent())
    assert p.state is S.ENFORCED
    assert p.verification["readback"] is True and p.verification["traffic"] == "blocked"
    assert IPv4Address(ATTACKER) in backend.state.blocked_sources
    assert backend.killed == [IPv4Address(ATTACKER)]
    clock.advance(121)
    service.reconcile()
    service.reconcile()
    assert service.repo.get(p.policy_id).state is S.EXPIRED
    assert IPv4Address(ATTACKER) not in backend.state.blocked_sources


def test_duplicate_decision_is_idempotent(svc):
    service, backend, _ = svc
    a = service.submit(intent())
    calls = backend.apply_calls
    b = service.submit(intent())
    assert a.policy_id == b.policy_id and backend.apply_calls == calls


def test_overlapping_owners_keep_block_until_last_expires(svc, clock):
    service, backend, _ = svc
    short = service.submit(intent(duration=60))
    clock.advance(10)
    long = service.submit(intent(duration=240, level=1))
    clock.advance(55)
    service.reconcile()
    assert service.repo.get(short.policy_id).state is S.EXPIRED
    assert service.repo.get(long.policy_id).state is S.ENFORCED
    assert IPv4Address(ATTACKER) in backend.state.blocked_sources  # still owned
    clock.advance(200)
    service.reconcile()
    service.reconcile()
    assert IPv4Address(ATTACKER) not in backend.state.blocked_sources


def test_ambiguous_timeout_becomes_unknown_then_resolves_by_readback(svc):
    service, backend, _ = svc
    backend.timeout_next = 1
    p = service.submit(intent())
    assert p.state is S.UNKNOWN  # never claims success it cannot prove
    service.reconcile()
    assert service.repo.get(p.policy_id).state is S.ENFORCED


def test_silent_noop_api_is_not_reported_enforced(svc):
    service, backend, _ = svc
    backend.drop_on_apply = True
    p = service.submit(intent())
    assert p.state is S.APPLIED_UNVERIFIED


def test_failure_retries_then_succeeds(svc):
    service, backend, _ = svc
    backend.fail_next = 1
    p = service.submit(intent())
    assert p.state is S.FAILED
    service.reconcile()  # FAILED -> APPLYING (retry)
    service.reconcile()
    assert service.repo.get(p.policy_id).state is S.ENFORCED


def test_firewall_reboot_is_detected_and_reconciled(svc):
    service, backend, _ = svc
    p = service.submit(intent())
    backend.state = backend.state.model_copy(update={"blocked_sources": frozenset()})  # reboot
    rep = service.reconcile()
    assert IPv4Address(ATTACKER) in backend.state.blocked_sources  # restored
    assert (p.policy_id, "enforced", "restored") in rep.transitions
    p = service.repo.get(p.policy_id)
    assert p.state is S.ENFORCED and "restored_at" in p.verification


def test_controller_restart_resumes_from_database(svc, lab_cfg, clock):
    service, backend, settings = svc
    p = service.submit(intent())
    fresh = PolicyService(
        repo=service.repo,
        validator=PolicyValidator(lab_cfg),
        backends=[backend],
        settings=settings,
        audit=service.audit,
        probe=MemoryProbe(backend),
        clock=clock,
    )
    assert not fresh.reconciled_since_start
    fresh.reconcile()
    assert fresh.reconciled_since_start
    assert fresh.repo.get(p.policy_id).state is S.ENFORCED


def test_monitor_mode_records_but_never_applies(svc):
    service, backend, settings = svc
    settings.set_mode(OperatingMode.MONITOR, "test")
    p = service.submit(intent())
    assert p.state is S.VALIDATED
    assert not backend.state.blocked_sources


def test_assisted_mode_requires_approval(svc):
    service, backend, settings = svc
    settings.set_mode(OperatingMode.ASSISTED, "test")
    p = service.submit(intent())
    assert p.state is S.PENDING_APPROVAL and not backend.state.blocked_sources
    p = service.approve(p.policy_id, "alice")
    assert p.state is S.ENFORCED and p.approved_by == "alice"


def test_revoke_rolls_back_with_readback(svc):
    service, backend, _ = svc
    p = service.submit(intent())
    p = service.revoke(p.policy_id, "alice", "false positive")
    assert p.state is S.ROLLED_BACK
    assert not backend.state.blocked_sources


def test_unsafe_mcp_request_rejected(svc):
    service, backend, _ = svc
    p = service.submit(intent(ip="10.77.50.10", origin=PolicyOrigin.MCP))
    assert p.state is S.REJECTED and not backend.state.blocked_sources


def test_unreachable_backend_never_claims_enforcement(svc):
    service, backend, _ = svc
    backend.unreachable = True
    p = service.submit(intent())
    assert p.state is S.UNKNOWN
    backend.unreachable = False
    service.reconcile()
    assert service.repo.get(p.policy_id).state is S.ENFORCED


def test_rate_limit_kind(svc):
    service, backend, _ = svc
    p = service.submit(intent(kind=PolicyKind.RATE_LIMIT, rate_profile=RateProfile.MODERATE))
    assert p.state is S.ENFORCED
    assert backend.state.rate_limited[IPv4Address(ATTACKER)] is RateProfile.MODERATE


def test_simulated_country_policy_blocks_mapped_sources_only(svc):
    service, backend, _ = svc
    t = CountryTarget(country_code="CN", direction="inbound", simulated=True)
    p = service.submit(intent(kind=PolicyKind.GEO_BLOCK, target=t, origin=PolicyOrigin.MCP))
    assert p.state is S.ENFORCED, p.history[-2:]
    mapped = {IPv4Address(f"10.77.10.{i}") for i in (10, 11, 12)}
    assert mapped <= backend.state.blocked_sources
    assert IPv4Address("10.77.20.10") not in backend.state.blocked_sources
    service.revoke(p.policy_id, "test", "done")
    assert not (mapped & backend.state.blocked_sources)


@pytest.mark.parametrize(
    "target,needle",
    [
        (CountryTarget(country_code="CN", direction="outbound", simulated=True), "only inbound"),
        (CountryTarget(country_code="FR", direction="inbound", simulated=True), "no simulated"),
        (CountryTarget(country_code="CN", direction="inbound", simulated=False), "GeoIP"),
    ],
)
def test_country_policy_rejections(svc, target, needle):
    service, backend, _ = svc
    p = service.submit(intent(kind=PolicyKind.GEO_BLOCK, target=target, origin=PolicyOrigin.MCP))
    assert p.state is S.REJECTED
    assert needle in p.history[-1].note
    assert not backend.state.blocked_sources
