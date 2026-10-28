"""network events (N1): Suricata flow/dns/tls/ssh/anomaly metadata

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-28
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "net_events",
        sa.Column("event_id", sa.String(length=40), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("src_ip", sa.String(length=15), nullable=False),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("event_id"),
    )
    op.create_index("ix_net_events_observed_at", "net_events", ["observed_at"])
    op.create_index("ix_net_events_src_ip", "net_events", ["src_ip"])


def downgrade() -> None:
    op.drop_index("ix_net_events_src_ip", table_name="net_events")
    op.drop_index("ix_net_events_observed_at", table_name="net_events")
    op.drop_table("net_events")
