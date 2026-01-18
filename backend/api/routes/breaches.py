"""
BREACH.AI v2 - Breach API Routes

API endpoints for managing breach sessions.
"""

from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.deps import get_current_user
from backend.db.database import get_db
from backend.services.breach import BreachService
from backend.db.models import User, Organization


router = APIRouter(prefix="/api/v2/breaches", tags=["breaches"])

# Type alias for auth tuple
AuthTuple = tuple[User, Organization]


# Request/Response Models
class BreachConfig(BaseModel):
    """Breach configuration."""
    timeout_hours: int = Field(default=24, ge=1, le=72)
    scope: list[str] = Field(default=[])
    rules: dict = Field(default={})
    aggressive_mode: bool = Field(default=False)
    skip_phases: list[str] = Field(default=[])


class CreateBreachRequest(BaseModel):
    """Request to create a breach session."""
    target_id: UUID
    config: Optional[BreachConfig] = None


class BreachResponse(BaseModel):
    """Breach session response."""
    id: UUID
    organization_id: UUID
    target_id: UUID
    target_url: str
    status: str
    current_phase: str
    breach_achieved: bool
    highest_access: Optional[str]
    systems_compromised: list[str]
    findings_count: int
    evidence_count: int
    started_at: Optional[str]
    completed_at: Optional[str]
    duration_seconds: Optional[int]
    error_message: Optional[str]

    class Config:
        from_attributes = True


class BreachStepResponse(BaseModel):
    """Breach step response."""
    id: UUID
    sequence_num: int
    phase: str
    module_name: str
    action: str
    target: str
    reasoning: str
    success: bool
    error: Optional[str]
    access_gained: Optional[str]
    duration_ms: Optional[int]
    started_at: Optional[str]
    completed_at: Optional[str]

    class Config:
        from_attributes = True


class BreachEvidenceResponse(BaseModel):
    """Breach evidence response."""
    id: UUID
    evidence_type: str
    description: str
    proves: str
    content_type: str
    is_redacted: bool
    severity: str
    created_at: str

    class Config:
        from_attributes = True


class BreachStatsResponse(BaseModel):
    """Breach statistics response."""
    total_breaches: int
    by_status: dict
    breaches_achieved: int
    success_rate: float
    avg_duration_seconds: float


# Endpoints
@router.post("", response_model=BreachResponse)
async def create_breach(
    request: CreateBreachRequest,
    db: AsyncSession = Depends(get_db),
    current: AuthTuple = Depends(get_current_user),
):
    """
    Create a new breach session.

    Creates a breach session for the specified target.
    The breach will be in 'pending' status until started.
    """
    user, org = current
    service = BreachService(db)

    try:
        config = request.config.model_dump() if request.config else {}
        session = await service.create_breach(
            target_id=request.target_id,
            organization_id=org.id,
            user_id=user.id,
            config=config,
        )
        return _session_to_response(session)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{session_id}/start", response_model=BreachResponse)
async def start_breach(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: AuthTuple = Depends(get_current_user),
):
    """
    Start a breach session.

    Starts the breach assessment in the background.
    Use the WebSocket endpoint or poll the status to monitor progress.
    """
    user, org = current
    service = BreachService(db)

    # Verify access
    session = await service.get_breach(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Breach session not found")
    if session.organization_id != org.id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        session = await service.start_breach(session_id)
        return _session_to_response(session)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("", response_model=list[BreachResponse])
async def list_breaches(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current: AuthTuple = Depends(get_current_user),
):
    """
    List breach sessions for the organization.
    """
    user, org = current
    service = BreachService(db)
    sessions = await service.list_breaches(
        organization_id=org.id,
        status=status,
        limit=limit,
        offset=offset,
    )
    return [_session_to_response(s) for s in sessions]


@router.get("/stats", response_model=BreachStatsResponse)
async def get_breach_stats(
    db: AsyncSession = Depends(get_db),
    current: AuthTuple = Depends(get_current_user),
):
    """
    Get breach statistics for the organization.
    """
    user, org = current
    service = BreachService(db)
    stats = await service.get_breach_stats(org.id)
    return BreachStatsResponse(**stats)


@router.get("/{session_id}", response_model=BreachResponse)
async def get_breach(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: AuthTuple = Depends(get_current_user),
):
    """
    Get a specific breach session.
    """
    user, org = current
    service = BreachService(db)
    session = await service.get_breach(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="Breach session not found")

    if session.organization_id != org.id:
        raise HTTPException(status_code=403, detail="Access denied")

    return _session_to_response(session)


@router.get("/{session_id}/steps", response_model=list[BreachStepResponse])
async def get_breach_steps(
    session_id: UUID,
    phase: Optional[str] = Query(None, description="Filter by phase"),
    db: AsyncSession = Depends(get_db),
    current: AuthTuple = Depends(get_current_user),
):
    """
    Get steps for a breach session.
    """
    user, org = current
    service = BreachService(db)

    # Verify access
    session = await service.get_breach(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Breach session not found")
    if session.organization_id != org.id:
        raise HTTPException(status_code=403, detail="Access denied")

    steps = await service.get_breach_steps(session_id, phase=phase)
    return [_step_to_response(s) for s in steps]


@router.get("/{session_id}/evidence", response_model=list[BreachEvidenceResponse])
async def get_breach_evidence(
    session_id: UUID,
    evidence_type: Optional[str] = Query(None, description="Filter by type"),
    db: AsyncSession = Depends(get_db),
    current: AuthTuple = Depends(get_current_user),
):
    """
    Get evidence for a breach session.
    """
    user, org = current
    service = BreachService(db)

    # Verify access
    session = await service.get_breach(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Breach session not found")
    if session.organization_id != org.id:
        raise HTTPException(status_code=403, detail="Access denied")

    evidence = await service.get_breach_evidence(session_id, evidence_type=evidence_type)
    return [_evidence_to_response(e) for e in evidence]


@router.get("/{session_id}/report")
async def get_breach_report(
    session_id: UUID,
    format: str = Query("json", description="Report format: json, markdown, html"),
    db: AsyncSession = Depends(get_db),
    current: AuthTuple = Depends(get_current_user),
):
    """
    Generate breach report.

    Returns a comprehensive report of the breach assessment.
    Available formats: json, markdown, html
    """
    user, org = current
    service = BreachService(db)

    # Verify access
    session = await service.get_breach(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Breach session not found")
    if session.organization_id != org.id:
        raise HTTPException(status_code=403, detail="Access denied")

    if session.status not in ["completed", "failed"]:
        raise HTTPException(
            status_code=400,
            detail="Report can only be generated for completed or failed breaches"
        )

    try:
        report = await service.generate_report(session_id, format=format)
        return report
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{session_id}/pause", response_model=BreachResponse)
async def pause_breach(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: AuthTuple = Depends(get_current_user),
):
    """
    Pause a running breach.
    """
    user, org = current
    service = BreachService(db)

    # Verify access
    session = await service.get_breach(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Breach session not found")
    if session.organization_id != org.id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        session = await service.pause_breach(session_id)
        return _session_to_response(session)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{session_id}/stop", response_model=BreachResponse)
async def stop_breach(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    current: AuthTuple = Depends(get_current_user),
):
    """
    Stop a breach and finalize results.
    """
    user, org = current
    service = BreachService(db)

    # Verify access
    session = await service.get_breach(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Breach session not found")
    if session.organization_id != org.id:
        raise HTTPException(status_code=403, detail="Access denied")

    try:
        session = await service.stop_breach(session_id)
        return _session_to_response(session)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# WebSocket for real-time updates
class ConnectionManager:
    """Manage WebSocket connections for breach updates."""

    def __init__(self):
        self.active_connections: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, session_id: str):
        await websocket.accept()
        if session_id not in self.active_connections:
            self.active_connections[session_id] = []
        self.active_connections[session_id].append(websocket)

    def disconnect(self, websocket: WebSocket, session_id: str):
        if session_id in self.active_connections:
            self.active_connections[session_id].remove(websocket)
            if not self.active_connections[session_id]:
                del self.active_connections[session_id]

    async def broadcast(self, session_id: str, message: dict):
        if session_id in self.active_connections:
            for connection in self.active_connections[session_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    pass


manager = ConnectionManager()


@router.websocket("/ws/{session_id}")
async def websocket_breach_updates(
    websocket: WebSocket,
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
):
    """
    WebSocket endpoint for real-time breach updates.

    Connect to receive live updates on breach progress:
    - phase_change: When breach moves to a new phase
    - step_complete: When a step finishes
    - evidence_found: When new evidence is collected
    - breach_complete: When breach finishes
    """
    session_str = str(session_id)
    await manager.connect(websocket, session_str)

    try:
        # Send initial status
        service = BreachService(db)
        session = await service.get_breach(session_id)

        if session:
            await websocket.send_json({
                "type": "connected",
                "session_id": session_str,
                "status": session.status,
                "phase": session.current_phase.value if session.current_phase else None,
            })

        # Keep connection open
        while True:
            try:
                data = await websocket.receive_text()
                # Handle ping/pong
                if data == "ping":
                    await websocket.send_text("pong")
            except WebSocketDisconnect:
                break

    finally:
        manager.disconnect(websocket, session_str)


# Helper for broadcasting updates (called from breach service)
async def broadcast_breach_update(session_id: str, update_type: str, data: dict):
    """Broadcast a breach update to all connected clients."""
    await manager.broadcast(session_id, {
        "type": update_type,
        "session_id": session_id,
        "data": data,
    })


# Response converters
def _session_to_response(session) -> BreachResponse:
    return BreachResponse(
        id=session.id,
        organization_id=session.organization_id,
        target_id=session.target_id,
        target_url=session.target_url,
        status=session.status,
        current_phase=session.current_phase.value if session.current_phase else "unknown",
        breach_achieved=session.breach_achieved or False,
        highest_access=session.highest_access.value if session.highest_access else None,
        systems_compromised=session.systems_compromised or [],
        findings_count=session.findings_count or 0,
        evidence_count=session.evidence_count or 0,
        started_at=session.started_at.isoformat() if session.started_at else None,
        completed_at=session.completed_at.isoformat() if session.completed_at else None,
        duration_seconds=session.duration_seconds,
        error_message=session.error_message,
    )


def _step_to_response(step) -> BreachStepResponse:
    return BreachStepResponse(
        id=step.id,
        sequence_num=step.sequence_num,
        phase=step.phase.value if step.phase else "unknown",
        module_name=step.module_name,
        action=step.action,
        target=step.target,
        reasoning=step.reasoning or "",
        success=step.success or False,
        error=step.error,
        access_gained=step.access_gained.value if step.access_gained else None,
        duration_ms=step.duration_ms,
        started_at=step.started_at.isoformat() if step.started_at else None,
        completed_at=step.completed_at.isoformat() if step.completed_at else None,
    )


def _evidence_to_response(evidence) -> BreachEvidenceResponse:
    return BreachEvidenceResponse(
        id=evidence.id,
        evidence_type=evidence.evidence_type,
        description=evidence.description,
        proves=evidence.proves,
        content_type=evidence.content_type or "application/json",
        is_redacted=evidence.is_redacted or False,
        severity=evidence.severity.value if evidence.severity else "info",
        created_at=evidence.created_at.isoformat() if evidence.created_at else "",
    )
