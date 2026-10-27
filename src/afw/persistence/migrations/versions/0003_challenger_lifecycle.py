"""challenger promotion lifecycle: evaluations and probations

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "challenger_evaluations",
        sa.Column("evaluation_id", sa.String(length=40), nullable=False),
        sa.Column("app_id", sa.String(length=32), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("evaluation_id"),
    )
    op.create_index(
        "ix_challenger_evaluations_evaluated_at", "challenger_evaluations", ["evaluated_at"]
    )
    op.create_table(
        "model_probations",
        sa.Column("probation_id", sa.String(length=40), nullable=False),
        sa.Column("app_id", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("probation_id"),
    )
    op.create_index("ix_model_probations_status", "model_probations", ["status"])


def downgrade() -> None:
    op.drop_index("ix_model_probations_status", table_name="model_probations")
    op.drop_table("model_probations")
    op.drop_index("ix_challenger_evaluations_evaluated_at", table_name="challenger_evaluations")
    op.drop_table("challenger_evaluations")
