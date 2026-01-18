"""
Initial schema - all BREACH.AI tables

Revision ID: 001_initial
Revises:
Create Date: 2026-01-17

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ============== ENUMS ==============
    # Use raw SQL to safely create enums (handles async properly)

    # Drop existing enums first (idempotent)
    op.execute('DROP TYPE IF EXISTS userrole CASCADE')
    op.execute('DROP TYPE IF EXISTS subscriptiontier CASCADE')
    op.execute('DROP TYPE IF EXISTS subscriptionstatus CASCADE')
    op.execute('DROP TYPE IF EXISTS scanstatus CASCADE')
    op.execute('DROP TYPE IF EXISTS scanmode CASCADE')
    op.execute('DROP TYPE IF EXISTS severity CASCADE')
    op.execute('DROP TYPE IF EXISTS breachphase CASCADE')
    op.execute('DROP TYPE IF EXISTS accesslevel CASCADE')

    # Create enums
    op.execute("CREATE TYPE userrole AS ENUM ('owner', 'admin', 'member', 'viewer')")
    op.execute("CREATE TYPE subscriptiontier AS ENUM ('free', 'starter', 'pro', 'enterprise')")
    op.execute("CREATE TYPE subscriptionstatus AS ENUM ('active', 'past_due', 'canceled', 'trialing')")
    op.execute("CREATE TYPE scanstatus AS ENUM ('pending', 'running', 'completed', 'failed', 'canceled')")
    op.execute("CREATE TYPE scanmode AS ENUM ('quick', 'normal', 'deep', 'chainbreaker')")
    op.execute("CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'info')")
    op.execute("CREATE TYPE breachphase AS ENUM ('recon', 'initial_access', 'foothold', 'escalation', 'lateral', 'data_access', 'proof')")
    op.execute("CREATE TYPE accesslevel AS ENUM ('none', 'anonymous', 'user', 'privileged_user', 'admin', 'database', 'cloud_user', 'cloud_admin', 'system', 'root')")

    # ============== TABLES ==============

    # Organizations
    op.create_table('organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), nullable=False),
        sa.Column('stripe_customer_id', sa.String(255), nullable=True),
        sa.Column('subscription_tier', postgresql.ENUM('free', 'starter', 'pro', 'enterprise', name='subscriptiontier', create_type=False), nullable=True, server_default='free'),
        sa.Column('subscription_status', postgresql.ENUM('active', 'past_due', 'canceled', 'trialing', name='subscriptionstatus', create_type=False), nullable=True, server_default='trialing'),
        sa.Column('stripe_subscription_id', sa.String(255), nullable=True),
        sa.Column('trial_ends_at', sa.DateTime(), nullable=True),
        sa.Column('max_scans_per_month', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('max_targets', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('max_team_members', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('max_concurrent_scans', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('scans_this_month', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('settings', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_organizations_slug', 'organizations', ['slug'], unique=True)
    op.create_index('ix_organizations_stripe_customer_id', 'organizations', ['stripe_customer_id'], unique=True)

    # Users
    op.create_table('users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('clerk_id', sa.String(255), nullable=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('avatar_url', sa.String(500), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('last_login_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    op.create_index('ix_users_clerk_id', 'users', ['clerk_id'], unique=True)

    # Organization Members (many-to-many)
    op.create_table('organization_members',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('role', postgresql.ENUM('owner', 'admin', 'member', 'viewer', name='userrole', create_type=False), nullable=False, server_default='member'),
        sa.Column('joined_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_org_member_unique', 'organization_members', ['organization_id', 'user_id'], unique=True)

    # Targets
    op.create_table('targets',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('url', sa.String(500), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_verified', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('verification_method', sa.String(50), nullable=True),
        sa.Column('verification_token', sa.String(100), nullable=True),
        sa.Column('verified_at', sa.DateTime(), nullable=True),
        sa.Column('settings', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Scans
    op.create_table('scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('target_url', sa.String(500), nullable=False),
        sa.Column('mode', postgresql.ENUM('quick', 'normal', 'deep', 'chainbreaker', name='scanmode', create_type=False), nullable=False, server_default='normal'),
        sa.Column('status', postgresql.ENUM('pending', 'running', 'completed', 'failed', 'canceled', name='scanstatus', create_type=False), nullable=False, server_default='pending'),
        sa.Column('progress', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('current_phase', sa.String(100), nullable=True),
        sa.Column('findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('critical_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('high_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('medium_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('low_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('info_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_business_impact', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('config', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('duration_seconds', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_scan_org_status', 'scans', ['organization_id', 'status'])
    op.create_index('ix_scan_created_at', 'scans', ['created_at'])

    # Findings
    op.create_table('findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('severity', postgresql.ENUM('critical', 'high', 'medium', 'low', 'info', name='severity', create_type=False), nullable=False),
        sa.Column('category', sa.String(100), nullable=False),
        sa.Column('endpoint', sa.String(500), nullable=False),
        sa.Column('method', sa.String(10), nullable=False, server_default='GET'),
        sa.Column('parameter', sa.String(255), nullable=True),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('evidence', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('business_impact', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('impact_explanation', sa.Text(), nullable=True),
        sa.Column('records_exposed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('pii_fields', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('fix_suggestion', sa.Text(), nullable=True),
        sa.Column('references', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('curl_command', sa.Text(), nullable=True),
        sa.Column('is_false_positive', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_resolved', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('discovered_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_finding_scan_severity', 'findings', ['scan_id', 'severity'])

    # API Keys
    op.create_table('api_keys',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('key_prefix', sa.String(10), nullable=False),
        sa.Column('key_hash', sa.String(255), nullable=False),
        sa.Column('scopes', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_api_key_hash', 'api_keys', ['key_hash'])

    # Audit Logs
    op.create_table('audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(50), nullable=False),
        sa.Column('resource_id', sa.String(100), nullable=True),
        sa.Column('details', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('ip_address', sa.String(50), nullable=True),
        sa.Column('user_agent', sa.String(500), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_audit_org_created', 'audit_logs', ['organization_id', 'created_at'])

    # Scheduled Scans
    op.create_table('scheduled_scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('cron_expression', sa.String(100), nullable=False),
        sa.Column('timezone', sa.String(50), nullable=False, server_default='UTC'),
        sa.Column('mode', postgresql.ENUM('quick', 'normal', 'deep', 'chainbreaker', name='scanmode', create_type=False), nullable=False, server_default='normal'),
        sa.Column('config', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('last_run_at', sa.DateTime(), nullable=True),
        sa.Column('next_run_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # ============== BREACH.AI v2 - KILL CHAIN TABLES ==============

    # Breach Sessions
    op.create_table('breach_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('started_by', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('target_url', sa.String(500), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default='pending'),
        sa.Column('current_phase', postgresql.ENUM('recon', 'initial_access', 'foothold', 'escalation', 'lateral', 'data_access', 'proof', name='breachphase', create_type=False), nullable=False, server_default='recon'),
        sa.Column('config', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('timeout_hours', sa.Integer(), nullable=False, server_default='24'),
        sa.Column('scope', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('rules_of_engagement', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('breach_achieved', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('highest_access', postgresql.ENUM('none', 'anonymous', 'user', 'privileged_user', 'admin', 'database', 'cloud_user', 'cloud_admin', 'system', 'root', name='accesslevel', create_type=False), nullable=False, server_default='none'),
        sa.Column('systems_compromised', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('evidence_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_business_impact', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('records_exposed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('duration_seconds', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['started_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_breach_session_org_status', 'breach_sessions', ['organization_id', 'status'])
    op.create_index('ix_breach_session_created', 'breach_sessions', ['created_at'])

    # Breach Steps
    op.create_table('breach_steps',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('sequence_num', sa.Integer(), nullable=False),
        sa.Column('phase', postgresql.ENUM('recon', 'initial_access', 'foothold', 'escalation', 'lateral', 'data_access', 'proof', name='breachphase', create_type=False), nullable=False),
        sa.Column('module_name', sa.String(100), nullable=False),
        sa.Column('action', sa.String(255), nullable=False),
        sa.Column('target', sa.String(500), nullable=False),
        sa.Column('parameters', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('reasoning', sa.Text(), nullable=True),
        sa.Column('expected_outcome', sa.Text(), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('result', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('access_gained', postgresql.ENUM('none', 'anonymous', 'user', 'privileged_user', 'admin', 'database', 'cloud_user', 'cloud_admin', 'system', 'root', name='accesslevel', create_type=False), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['session_id'], ['breach_sessions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_breach_step_session', 'breach_steps', ['session_id'])
    op.create_index('ix_breach_step_phase', 'breach_steps', ['phase'])

    # Breach Evidence
    op.create_table('breach_evidence',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('step_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('evidence_type', sa.String(50), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('proves', sa.Text(), nullable=False),
        sa.Column('content', postgresql.JSON(astext_type=sa.Text()), nullable=False, server_default='{}'),
        sa.Column('content_type', sa.String(100), nullable=False, server_default='application/json'),
        sa.Column('content_hash', sa.String(64), nullable=True),
        sa.Column('is_redacted', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('redaction_notes', sa.Text(), nullable=True),
        sa.Column('severity', postgresql.ENUM('critical', 'high', 'medium', 'low', 'info', name='severity', create_type=False), nullable=False, server_default='info'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.ForeignKeyConstraint(['session_id'], ['breach_sessions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['step_id'], ['breach_steps.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_breach_evidence_session', 'breach_evidence', ['session_id'])
    op.create_index('ix_breach_evidence_type', 'breach_evidence', ['evidence_type'])

    # Brain Memory (Learning Engine)
    op.create_table('brain_memory',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('target_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('memory_type', sa.String(50), nullable=False),
        sa.Column('key', sa.String(255), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('access_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_accessed', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['target_id'], ['targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_brain_memory_target', 'brain_memory', ['target_id'])
    op.create_index('ix_brain_memory_type', 'brain_memory', ['memory_type'])
    op.create_index('ix_brain_memory_key', 'brain_memory', ['key'], unique=True)


def downgrade() -> None:
    # Drop tables in reverse order (respecting foreign key constraints)
    op.drop_table('brain_memory')
    op.drop_table('breach_evidence')
    op.drop_table('breach_steps')
    op.drop_table('breach_sessions')
    op.drop_table('scheduled_scans')
    op.drop_table('audit_logs')
    op.drop_table('api_keys')
    op.drop_table('findings')
    op.drop_table('scans')
    op.drop_table('targets')
    op.drop_table('organization_members')
    op.drop_table('users')
    op.drop_table('organizations')

    # Drop enums
    op.execute('DROP TYPE IF EXISTS accesslevel')
    op.execute('DROP TYPE IF EXISTS breachphase')
    op.execute('DROP TYPE IF EXISTS severity')
    op.execute('DROP TYPE IF EXISTS scanmode')
    op.execute('DROP TYPE IF EXISTS scanstatus')
    op.execute('DROP TYPE IF EXISTS subscriptionstatus')
    op.execute('DROP TYPE IF EXISTS subscriptiontier')
    op.execute('DROP TYPE IF EXISTS userrole')
