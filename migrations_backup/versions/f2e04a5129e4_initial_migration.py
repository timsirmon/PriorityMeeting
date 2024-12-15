"""Initial migration

Revision ID: f2e04a5129e4
Revises: 
Create Date: 2024-12-13 07:13:01.165873

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f2e04a5129e4'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('topic') as batch_op:
        batch_op.add_column(sa.Column('user_id', sa.Integer(), nullable=False))
        batch_op.create_foreign_key('fk_topic_user_id', 'user', ['user_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('topic', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('user_id')

    # ### end Alembic commands ###
