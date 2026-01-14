"""Add cancelled_at field to ScheduledTask

Revision ID: 202601132210
Revises: 
Create Date: 2026-01-13 22:10:00.000000

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '202601132210'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('scheduled_tasks', sa.Column('cancelled_at', sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column('scheduled_tasks', 'cancelled_at')
