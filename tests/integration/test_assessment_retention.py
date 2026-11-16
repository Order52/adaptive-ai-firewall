"""Assessment retention: old unreferenced rows age out; cited evidence is never lost."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from sqlalchemy import insert, select

from afw.container import build_container
from afw.domain.adaptation import Feedback, FeedbackLabel
from afw.domain.risk import RiskAssessment, RiskBand
from afw.persistence import schema as t
from afw.services.runtime import ASSESSMENT_RETENTION

NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


def _ra(assessment_id: str, age_days: float) -> RiskAssessment:
    at = NOW - timedelta(days=age_days)
    return RiskAssessment(
        assessment_id=assessment_id,
        app_id="rental",
        source_ip=IPv4Address("10.77.20.150"),
        assessed_at=at,
        window_end=at,
        score=10.0,
        band=RiskBand.LOW,
        evidence=(),
        corroborating_categories=(),
        model_version=None,
        profile_version=1,
    )


def _ids(c) -> set[str]:
    with c.analysis.engine.connect() as conn:
        return {r[0] for r in conn.execute(select(t.assessments.c.assessment_id))}


def test_old_unreferenced_assessments_are_purged_and_cited_ones_survive(settings):
    c = build_container(settings, simulated=True)
    for name, age in [
        ("risk-fresh000001", 1),
        ("risk-old0000001", 200),  # unreferenced: goes
        ("risk-oldpolicy01", 200),  # cited by a policy: stays
        ("risk-oldfeedback1", 200),  # cited by feedback: stays
        ("risk-justinside01", ASSESSMENT_RETENTION.days - 1),
    ]:
        c.analysis.add_assessment(_ra(name, age))
    with c.analysis.engine.begin() as conn:
        conn.execute(
            insert(t.policies).values(
                policy_id="pol-x",
                idempotency_key="k",
                state="expired",
                updated_at=NOW.replace(tzinfo=None),
                body='{"intent": {"risk_assessment_id": "risk-oldpolicy01"}}',
            )
        )
    c.adaptation.add_feedback(
        Feedback(
            feedback_id="fb-1",
            created_at=NOW,
            author="op",
            label=FeedbackLabel.FALSE_POSITIVE,
            app_id="rental",
            assessment_id="risk-oldfeedback1",
        )
    )

    purged = c.analysis.purge_assessments_before(NOW - ASSESSMENT_RETENTION)

    assert purged == 1
    assert _ids(c) == {
        "risk-fresh000001",
        "risk-oldpolicy01",
        "risk-oldfeedback1",
        "risk-justinside01",
    }
    assert c.analysis.get_assessment("risk-oldpolicy01") is not None  # explanation still works


def test_purge_is_idempotent_and_handles_an_empty_table(settings):
    c = build_container(settings, simulated=True)
    assert c.analysis.purge_assessments_before(NOW) == 0
    c.analysis.add_assessment(_ra("risk-old0000002", 400))
    assert c.analysis.purge_assessments_before(NOW - ASSESSMENT_RETENTION) == 1
    assert c.analysis.purge_assessments_before(NOW - ASSESSMENT_RETENTION) == 0


def test_purge_handles_more_rows_than_one_batch(settings):
    c = build_container(settings, simulated=True)
    for i in range(1300):
        c.analysis.add_assessment(_ra(f"risk-bulk{i:08d}", 300))
    assert c.analysis.purge_assessments_before(NOW - ASSESSMENT_RETENTION, batch=500) == 1300
    assert _ids(c) == set()


def test_reclaim_space_shrinks_an_incremental_vacuum_database(settings):
    c = build_container(settings, simulated=True)
    eng = c.analysis.engine
    if eng.dialect.name != "sqlite":
        return
    with eng.connect() as conn:  # converting an existing file needs VACUUM
        conn.exec_driver_sql("PRAGMA auto_vacuum=2")
        conn.commit()
        conn.exec_driver_sql("VACUUM")
        assert conn.exec_driver_sql("PRAGMA auto_vacuum").scalar() == 2
    for i in range(2000):
        c.analysis.add_assessment(_ra(f"risk-vac{i:09d}", 300))
    size = lambda: eng.connect().exec_driver_sql("PRAGMA page_count").scalar()
    before = size()
    c.analysis.purge_assessments_before(NOW - ASSESSMENT_RETENTION)
    c.analysis.reclaim_space(pages=100_000)
    assert size() < before
    c.analysis.reclaim_space()  # a second call on a compact database is harmless


def test_controller_retention_job_uses_the_assessment_window(settings):
    c = build_container(settings, simulated=True)
    c.analysis.add_assessment(_ra("risk-ancient00001", 1000))
    c.controller.clock = lambda: NOW
    c.controller._retention()
    assert _ids(c) == set()
