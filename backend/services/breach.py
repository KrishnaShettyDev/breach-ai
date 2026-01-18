"""
BREACH.AI v2 - Breach Service

Service layer for managing breach sessions.
Handles creation, execution, status tracking, and report generation.
"""

import asyncio
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.db.models import (
    BreachSession as BreachSessionModel,
    BreachStep as BreachStepModel,
    BreachEvidence as BreachEvidenceModel,
    BrainMemory as BrainMemoryModel,
    Target,
    User,
    Organization,
    BreachPhase as DBBreachPhase,
    AccessLevel as DBAccessLevel,
    Severity,
)
from backend.breach.core.orchestrator import KillChainOrchestrator
from backend.breach.core.killchain import (
    BreachSession,
    BreachStep,
    Evidence,
    BreachPhase,
    AccessLevel,
)
from backend.breach.report.brutal_report import BrutalReportGenerator
from backend.breach.utils.http import HTTPClient


class BreachService:
    """
    Service for managing breach sessions.
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self._active_breaches: dict[str, asyncio.Task] = {}

    async def create_breach(
        self,
        target_id: UUID,
        organization_id: UUID,
        user_id: UUID,
        config: dict = None,
    ) -> BreachSessionModel:
        """
        Create a new breach session.
        """
        # Get target
        result = await self.db.execute(
            select(Target).where(Target.id == target_id)
        )
        target = result.scalar_one_or_none()

        if not target:
            raise ValueError("Target not found")

        if not target.is_verified:
            raise ValueError("Target must be verified before breach assessment")

        # Create session
        session = BreachSessionModel(
            organization_id=organization_id,
            target_id=target_id,
            started_by=user_id,
            target_url=target.url,
            status="pending",
            current_phase=DBBreachPhase.RECON,
            config=config or {},
            timeout_hours=config.get("timeout_hours", 24) if config else 24,
            scope=config.get("scope", [target.url]) if config else [target.url],
            rules_of_engagement=config.get("rules", {}) if config else {},
        )

        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)

        return session

    async def start_breach(self, session_id: UUID) -> BreachSessionModel:
        """
        Start a breach session.
        """
        # Get session
        session = await self.get_breach(session_id)
        if not session:
            raise ValueError("Breach session not found")

        if session.status not in ["pending", "paused"]:
            raise ValueError(f"Cannot start breach in {session.status} state")

        # Update status
        session.status = "running"
        session.started_at = datetime.utcnow()
        await self.db.commit()

        # Start breach in background
        task = asyncio.create_task(
            self._run_breach(session_id)
        )
        self._active_breaches[str(session_id)] = task

        return session

    async def _run_breach(self, session_id: UUID):
        """
        Run the breach assessment in background.
        """
        session = await self.get_breach(session_id)
        if not session:
            return

        http_client = None
        try:
            # Initialize HTTP client
            http_client = HTTPClient(
                base_url=session.target_url,
                rate_limit=50,
            )

            # Initialize orchestrator
            orchestrator = KillChainOrchestrator(http_client=http_client)

            # Run breach
            result = await orchestrator.run_breach(
                target=session.target_url,
                timeout_hours=session.timeout_hours,
                scope=session.scope,
                rules=session.rules_of_engagement,
            )

            # Save results to database
            await self._save_breach_results(session_id, result)

        except Exception as e:
            # Update session with error
            await self._update_session_error(session_id, str(e))

        finally:
            if http_client:
                await http_client.close()

            # Remove from active breaches
            self._active_breaches.pop(str(session_id), None)

    async def _save_breach_results(self, session_id: UUID, result: BreachSession):
        """
        Save breach results to database.
        """
        # Get fresh session from DB
        db_session = await self.get_breach(session_id)
        if not db_session:
            return

        # Update session
        db_session.status = "completed"
        db_session.breach_achieved = result.breach_achieved
        db_session.highest_access = DBAccessLevel(result.highest_access.value)
        db_session.systems_compromised = result.systems_compromised
        db_session.findings_count = len([s for s in result.steps if s.success])
        db_session.evidence_count = len(result.evidence_collected)
        db_session.completed_at = datetime.utcnow()
        db_session.duration_seconds = int(result.get_duration_seconds())

        # Save steps
        for step in result.steps:
            db_step = BreachStepModel(
                session_id=session_id,
                sequence_num=step.sequence_num,
                phase=DBBreachPhase(step.phase.value),
                module_name=step.module_name,
                action=step.action,
                target=step.target,
                parameters=step.parameters,
                reasoning=step.reasoning,
                expected_outcome=step.expected_outcome,
                success=step.success,
                result=step.result.to_dict() if step.result else {},
                error=step.error,
                access_gained=DBAccessLevel(step.result.access_gained.value) if step.result and step.result.access_gained else None,
                started_at=step.started_at,
                completed_at=step.completed_at,
                duration_ms=step.duration_ms,
            )
            self.db.add(db_step)

        # Save evidence
        for evidence in result.evidence_collected:
            db_evidence = BreachEvidenceModel(
                session_id=session_id,
                evidence_type=evidence.evidence_type.value,
                description=evidence.description,
                proves=evidence.proves,
                content=evidence.to_dict(),
                content_type=evidence.content_type,
                is_redacted=evidence.is_redacted,
                redaction_notes=evidence.redaction_notes,
                severity=Severity(evidence.severity.value),
            )
            self.db.add(db_evidence)

        await self.db.commit()

    async def _update_session_error(self, session_id: UUID, error: str):
        """
        Update session with error status.
        """
        await self.db.execute(
            update(BreachSessionModel)
            .where(BreachSessionModel.id == session_id)
            .values(
                status="failed",
                error_message=error,
                completed_at=datetime.utcnow(),
            )
        )
        await self.db.commit()

    async def get_breach(self, session_id: UUID) -> Optional[BreachSessionModel]:
        """
        Get a breach session by ID.
        """
        result = await self.db.execute(
            select(BreachSessionModel)
            .where(BreachSessionModel.id == session_id)
            .options(
                selectinload(BreachSessionModel.steps),
                selectinload(BreachSessionModel.evidence),
            )
        )
        return result.scalar_one_or_none()

    async def list_breaches(
        self,
        organization_id: UUID,
        status: str = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[BreachSessionModel]:
        """
        List breach sessions for an organization.
        """
        query = (
            select(BreachSessionModel)
            .where(BreachSessionModel.organization_id == organization_id)
            .order_by(BreachSessionModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )

        if status:
            query = query.where(BreachSessionModel.status == status)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_breach_steps(
        self,
        session_id: UUID,
        phase: str = None,
    ) -> list[BreachStepModel]:
        """
        Get steps for a breach session.
        """
        query = (
            select(BreachStepModel)
            .where(BreachStepModel.session_id == session_id)
            .order_by(BreachStepModel.sequence_num)
        )

        if phase:
            query = query.where(BreachStepModel.phase == DBBreachPhase(phase))

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def get_breach_evidence(
        self,
        session_id: UUID,
        evidence_type: str = None,
    ) -> list[BreachEvidenceModel]:
        """
        Get evidence for a breach session.
        """
        query = (
            select(BreachEvidenceModel)
            .where(BreachEvidenceModel.session_id == session_id)
            .order_by(BreachEvidenceModel.created_at)
        )

        if evidence_type:
            query = query.where(BreachEvidenceModel.evidence_type == evidence_type)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def pause_breach(self, session_id: UUID) -> BreachSessionModel:
        """
        Pause a running breach.
        """
        session = await self.get_breach(session_id)
        if not session:
            raise ValueError("Breach session not found")

        if session.status != "running":
            raise ValueError("Can only pause running breaches")

        # Cancel the task
        task = self._active_breaches.get(str(session_id))
        if task:
            task.cancel()

        session.status = "paused"
        await self.db.commit()

        return session

    async def stop_breach(self, session_id: UUID) -> BreachSessionModel:
        """
        Stop a breach and finalize results.
        """
        session = await self.get_breach(session_id)
        if not session:
            raise ValueError("Breach session not found")

        if session.status not in ["running", "paused"]:
            raise ValueError("Can only stop running or paused breaches")

        # Cancel the task
        task = self._active_breaches.get(str(session_id))
        if task:
            task.cancel()

        session.status = "completed"
        session.completed_at = datetime.utcnow()
        if session.started_at:
            session.duration_seconds = int(
                (session.completed_at - session.started_at).total_seconds()
            )
        await self.db.commit()

        return session

    async def generate_report(
        self,
        session_id: UUID,
        format: str = "json",
    ) -> dict | str:
        """
        Generate breach report.
        """
        session = await self.get_breach(session_id)
        if not session:
            raise ValueError("Breach session not found")

        # Convert DB model to core BreachSession for report generation
        core_session = self._db_to_core_session(session)

        # Generate report
        generator = BrutalReportGenerator()

        if format == "markdown":
            return generator.generate_markdown(core_session)
        elif format == "html":
            return generator.generate_html(core_session)
        else:
            return generator.generate(core_session)

    def _db_to_core_session(self, db_session: BreachSessionModel) -> BreachSession:
        """
        Convert database model to core BreachSession.
        """
        from backend.breach.core.killchain import (
            BreachSession as CoreSession,
            BreachStep as CoreStep,
            Evidence as CoreEvidence,
            BreachPhase as CorePhase,
            AccessLevel as CoreAccessLevel,
            EvidenceType,
            Severity as CoreSeverity,
        )

        # Convert steps
        steps = []
        for db_step in db_session.steps:
            step = CoreStep(
                id=str(db_step.id),
                session_id=str(db_step.session_id),
                sequence_num=db_step.sequence_num,
                phase=CorePhase(db_step.phase.value),
                module_name=db_step.module_name,
                action=db_step.action,
                target=db_step.target,
                parameters=db_step.parameters,
                reasoning=db_step.reasoning,
                expected_outcome=db_step.expected_outcome,
                success=db_step.success,
                error=db_step.error,
                started_at=db_step.started_at,
                completed_at=db_step.completed_at,
                duration_ms=db_step.duration_ms,
            )
            steps.append(step)

        # Convert evidence
        evidence = []
        for db_evidence in db_session.evidence:
            ev = CoreEvidence(
                id=str(db_evidence.id),
                evidence_type=EvidenceType(db_evidence.evidence_type),
                description=db_evidence.description,
                proves=db_evidence.proves,
                content=db_evidence.content,
                content_type=db_evidence.content_type,
                is_redacted=db_evidence.is_redacted,
                redaction_notes=db_evidence.redaction_notes,
                severity=CoreSeverity(db_evidence.severity.value),
                timestamp=db_evidence.created_at,
            )
            evidence.append(ev)

        # Create core session
        return CoreSession(
            id=str(db_session.id),
            target=db_session.target_url,
            current_phase=CorePhase(db_session.current_phase.value),
            is_running=db_session.status == "running",
            is_complete=db_session.status == "completed",
            breach_achieved=db_session.breach_achieved,
            highest_access=CoreAccessLevel(db_session.highest_access.value),
            systems_compromised=db_session.systems_compromised or [],
            steps=steps,
            evidence_collected=evidence,
            started_at=db_session.started_at,
            completed_at=db_session.completed_at,
        )

    async def get_breach_stats(self, organization_id: UUID) -> dict:
        """
        Get breach statistics for an organization.
        """
        from sqlalchemy import func

        # Total breaches
        total_result = await self.db.execute(
            select(func.count(BreachSessionModel.id))
            .where(BreachSessionModel.organization_id == organization_id)
        )
        total = total_result.scalar() or 0

        # By status
        status_result = await self.db.execute(
            select(
                BreachSessionModel.status,
                func.count(BreachSessionModel.id)
            )
            .where(BreachSessionModel.organization_id == organization_id)
            .group_by(BreachSessionModel.status)
        )
        by_status = {row[0]: row[1] for row in status_result.all()}

        # Breach achieved count
        achieved_result = await self.db.execute(
            select(func.count(BreachSessionModel.id))
            .where(BreachSessionModel.organization_id == organization_id)
            .where(BreachSessionModel.breach_achieved == True)
        )
        achieved = achieved_result.scalar() or 0

        # Average duration
        duration_result = await self.db.execute(
            select(func.avg(BreachSessionModel.duration_seconds))
            .where(BreachSessionModel.organization_id == organization_id)
            .where(BreachSessionModel.duration_seconds.isnot(None))
        )
        avg_duration = duration_result.scalar() or 0

        return {
            "total_breaches": total,
            "by_status": by_status,
            "breaches_achieved": achieved,
            "success_rate": (achieved / total * 100) if total > 0 else 0,
            "avg_duration_seconds": avg_duration,
        }
