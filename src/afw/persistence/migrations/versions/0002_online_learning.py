"""online (shadow) learning: reputation, checkpoints, ledger, shadow scores

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-27
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "source_reputation",
        sa.Column("source_ip", sa.String(length=15), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("taint_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("taint_reason", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("source_ip"),
    )
    op.create_index("ix_source_reputation_last_seen", "source_reputation", ["last_seen"])
    op.create_table(
        "challenger_checkpoints",
        sa.Column("checkpoint_id", sa.String(length=40), nullable=False),
        sa.Column("app_id", sa.String(length=32), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("checkpoint_id"),
        sa.UniqueConstraint("app_id", "seq", name="uq_challenger_checkpoints_app_seq"),
    )
    op.create_table(
        "learned_windows",
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("app_id", sa.String(length=32), nullable=False),
        sa.Column("source_ip", sa.String(length=15), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("checkpoint_id", sa.String(length=40), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("fingerprint"),
    )
    op.create_index("ix_learned_windows_source_ip", "learned_windows", ["source_ip"])
    op.create_index("ix_learned_windows_window_end", "learned_windows", ["window_end"])
    op.create_index("ix_learned_windows_checkpoint_id", "learned_windows", ["checkpoint_id"])
    op.create_table(
        "shadow_scores",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("app_id", sa.String(length=32), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_shadow_scores_window_end", "shadow_scores", ["window_end"])


def downgrade() -> None:
    op.drop_index("ix_shadow_scores_window_end", table_name="shadow_scores")
    op.drop_table("shadow_scores")
    for ix in ("checkpoint_id", "window_end", "source_ip"):
        op.drop_index(f"ix_learned_windows_{ix}", table_name="learned_windows")
    op.drop_table("learned_windows")
    op.drop_table("challenger_checkpoints")
    op.drop_index("ix_source_reputation_last_seen", table_name="source_reputation")
    op.drop_table("source_reputation")
