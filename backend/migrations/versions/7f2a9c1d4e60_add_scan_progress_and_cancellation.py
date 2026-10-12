"""Add scan progress and cancellation fields.

Revision ID: 7f2a9c1d4e60
Revises: 11c4a0c70a51
"""

from alembic import op
import sqlalchemy as sa


revision = "7f2a9c1d4e60"
down_revision = "11c4a0c70a51"
branch_labels = None
depends_on = None



def upgrade() -> None:
    with op.batch_alter_table("scans") as batch_op:
        existing_columns = {
            column["name"]
            for column in sa.inspect(op.get_bind()).get_columns("scans")
        }

        if "current_scanner" not in existing_columns:
            batch_op.add_column(
                sa.Column("current_scanner", sa.String(length=100), nullable=True)
            )

        if "progress_percent" not in existing_columns:
            batch_op.add_column(
                sa.Column(
                    "progress_percent",
                    sa.Integer(),
                    server_default="0",
                    nullable=False,
                )
            )

        if "cancel_requested" not in existing_columns:
            batch_op.add_column(
                sa.Column(
                    "cancel_requested",
                    sa.Boolean(),
                    server_default=sa.false(),
                    nullable=False,
                )
            )

        existing_checks = {
            constraint["name"]
            for constraint in sa.inspect(op.get_bind()).get_check_constraints("scans")
        }

        if "ck_scan_progress_percent" not in existing_checks:
            batch_op.create_check_constraint(
                "ck_scan_progress_percent",
                "progress_percent >= 0 AND progress_percent <= 100",
            )


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch_op:
        existing_columns = {
            column["name"]
            for column in sa.inspect(op.get_bind()).get_columns("scans")
        }

        existing_checks = {
            constraint["name"]
            for constraint in sa.inspect(op.get_bind()).get_check_constraints("scans")
        }

        if "ck_scan_progress_percent" in existing_checks:
            batch_op.drop_constraint(
                "ck_scan_progress_percent",
                type_="check",
            )

        for column_name in (
            "cancel_requested",
            "progress_percent",
            "current_scanner",
        ):
            if column_name in existing_columns:
                batch_op.drop_column(column_name)
