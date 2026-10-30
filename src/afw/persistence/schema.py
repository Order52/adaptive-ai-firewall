"""Relational schema (SQLAlchemy Core). Indexed columns + validated JSON body.

Portable to PostgreSQL: only standard types are used; JSON bodies are TEXT.
Schema changes go through Alembic migrations (``afw db upgrade``).
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
)

metadata = MetaData()

observations = Table(
    "observations",
    metadata,
    Column("event_id", String(40), primary_key=True),
    Column("request_id", String(64), nullable=False, unique=True),
    Column("app_id", String(32), nullable=False),
    Column("observed_at", DateTime(timezone=True), nullable=False, index=True),
    Column("client_ip", String(15), nullable=False, index=True),
    Column("body", Text, nullable=False),
)

ids_alerts = Table(
    "ids_alerts",
    metadata,
    Column("event_id", String(40), primary_key=True),
    Column("observed_at", DateTime(timezone=True), nullable=False, index=True),
    Column("src_ip", String(15), nullable=False),
    Column("body", Text, nullable=False),
)

net_events = Table(
    "net_events",
    metadata,
    Column("event_id", String(40), primary_key=True),
    Column("observed_at", DateTime(timezone=True), nullable=False, index=True),
    Column("src_ip", String(15), nullable=False, index=True),
    Column("kind", String(8), nullable=False),
    Column("body", Text, nullable=False),
)

features = Table(
    "features",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("app_id", String(32), nullable=False),
    Column("source_ip", String(15), nullable=False),
    Column("window_end", DateTime(timezone=True), nullable=False, index=True),
    Column("dataset_id", String(64), nullable=True, index=True),
    Column("body", Text, nullable=False),
)

detections = Table(
    "detections",
    metadata,
    Column("detection_id", String(40), primary_key=True),
    Column("window_end", DateTime(timezone=True), nullable=False, index=True),
    Column("source_ip", String(15), nullable=False),
    Column("detector", String(32), nullable=False),
    Column("anomalous", Boolean, nullable=False),
    Column("body", Text, nullable=False),
)

assessments = Table(
    "assessments",
    metadata,
    Column("assessment_id", String(40), primary_key=True),
    Column("assessed_at", DateTime(timezone=True), nullable=False, index=True),
    Column("source_ip", String(15), nullable=False, index=True),
    Column("score", Float, nullable=False, index=True),
    Column("body", Text, nullable=False),
)

profiles = Table(
    "profiles",
    metadata,
    Column("profile_id", String(40), primary_key=True),
    Column("app_id", String(32), nullable=False),
    Column("version", Integer, nullable=False),
    Column("status", String(16), nullable=False),
    Column("body", Text, nullable=False),
    UniqueConstraint("app_id", "version", name="uq_profile_version"),
)

models = Table(
    "models",
    metadata,
    Column("model_id", String(40), primary_key=True),
    Column("app_id", String(32), nullable=False),
    Column("detector", String(32), nullable=False),
    Column("status", String(16), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("body", Text, nullable=False),
)

policies = Table(
    "policies",
    metadata,
    Column("policy_id", String(40), primary_key=True),
    Column("idempotency_key", String(64), nullable=False, index=True),
    Column("state", String(24), nullable=False, index=True),
    Column("updated_at", DateTime(timezone=True), nullable=False, index=True),
    Column("body", Text, nullable=False),
)

drift_reports = Table(
    "drift_reports",
    metadata,
    Column("report_id", String(40), primary_key=True),
    Column("app_id", String(32), nullable=False),
    Column("detected_at", DateTime(timezone=True), nullable=False, index=True),
    Column("body", Text, nullable=False),
)

feedback = Table(
    "feedback",
    metadata,
    Column("feedback_id", String(40), primary_key=True),
    Column("app_id", String(32), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("body", Text, nullable=False),
)

evaluations = Table(
    "evaluations",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("app_id", String(32), nullable=False),
    Column("evaluated_at", DateTime(timezone=True), nullable=False),
    Column("body", Text, nullable=False),
)

settings = Table(
    "settings",
    metadata,
    Column("key", String(64), primary_key=True),
    Column("value", Text, nullable=False),
)

audit = Table(
    "audit",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("at", DateTime(timezone=True), nullable=False, index=True),
    Column("actor", String(64), nullable=False),
    Column("action", String(64), nullable=False),
    Column("subject", String(64), nullable=False),
    Column("detail", Text, nullable=False),
)

experiment_results = Table(
    "experiment_results",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("experiment", String(64), nullable=False, index=True),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("body", Text, nullable=False),
)

# --- online (shadow) learning (migration 0002, ADR-028)
source_reputation = Table(
    "source_reputation",
    metadata,
    Column("source_ip", String(15), primary_key=True),
    Column("first_seen", DateTime(timezone=True), nullable=False),
    Column("last_seen", DateTime(timezone=True), nullable=False, index=True),
    Column("taint_until", DateTime(timezone=True), nullable=True),
    Column("taint_reason", String(64), nullable=True),
)

challenger_checkpoints = Table(
    "challenger_checkpoints",
    metadata,
    Column("checkpoint_id", String(40), primary_key=True),
    Column("app_id", String(32), nullable=False),
    Column("seq", Integer, nullable=False),
    Column("status", String(16), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("body", Text, nullable=False),
    UniqueConstraint("app_id", "seq", name="uq_challenger_checkpoints_app_seq"),
)

learned_windows = Table(
    "learned_windows",
    metadata,
    Column("fingerprint", String(64), primary_key=True),
    Column("app_id", String(32), nullable=False),
    Column("source_ip", String(15), nullable=False, index=True),
    Column("window_end", DateTime(timezone=True), nullable=False, index=True),
    Column("checkpoint_id", String(40), nullable=False, index=True),
    Column("body", Text, nullable=False),
)

shadow_scores = Table(
    "shadow_scores",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("app_id", String(32), nullable=False),
    Column("window_end", DateTime(timezone=True), nullable=False, index=True),
    Column("body", Text, nullable=False),
)

# --- challenger promotion lifecycle (migration 0003, ADR-030)
challenger_evaluations = Table(
    "challenger_evaluations",
    metadata,
    Column("evaluation_id", String(40), primary_key=True),
    Column("app_id", String(32), nullable=False),
    Column("evaluated_at", DateTime(timezone=True), nullable=False, index=True),
    Column("body", Text, nullable=False),
)

model_probations = Table(
    "model_probations",
    metadata,
    Column("probation_id", String(40), primary_key=True),
    Column("app_id", String(32), nullable=False),
    Column("status", String(16), nullable=False, index=True),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("body", Text, nullable=False),
)

Index("ix_detections_anomalous", detections.c.anomalous, detections.c.window_end)
