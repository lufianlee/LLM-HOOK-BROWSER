from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzer.engine import analyze_chain, analyze_single_request
from app.config import settings
from app.database import get_session
from app.event_bus import broadcast, subscribe, unsubscribe
from app.models import CapturedRequest, Finding, Severity, Simulation
from app.schemas import (
    AnalyzeRequest,
    CapturedRequestOut,
    ChainAnalyzeRequest,
    DomainConfig,
    FindingOut,
    SimulationOut,
    SimulationRequest,
    StatsOut,
)
from app.simulator.attacker import run_simulation

router = APIRouter()


# ─── Requests ────────────────────────────────────────────────

@router.get("/requests", response_model=list[CapturedRequestOut])
async def list_requests(
    limit: int = 50,
    offset: int = 0,
    host: str | None = None,
    method: str | None = None,
    session: AsyncSession = Depends(get_session),
):
    stmt = select(CapturedRequest).order_by(desc(CapturedRequest.timestamp))
    if host:
        stmt = stmt.where(CapturedRequest.host.contains(host))
    if method:
        stmt = stmt.where(CapturedRequest.method == method.upper())
    stmt = stmt.offset(offset).limit(limit)
    result = await session.execute(stmt)
    return result.scalars().all()


@router.get("/requests/{request_id}", response_model=CapturedRequestOut)
async def get_request(request_id: int, session: AsyncSession = Depends(get_session)):
    req = await session.get(CapturedRequest, request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    return req


# ─── Analysis ────────────────────────────────────────────────

@router.post("/analyze/single", response_model=list[FindingOut])
async def analyze_single(body: AnalyzeRequest, session: AsyncSession = Depends(get_session)):
    findings = await analyze_single_request(session, body.request_id)
    result = [FindingOut.model_validate(f) for f in findings]
    await broadcast("new_findings", [r.model_dump() for r in result])
    return result


@router.post("/analyze/chain", response_model=list[FindingOut])
async def analyze_chain_endpoint(body: ChainAnalyzeRequest, session: AsyncSession = Depends(get_session)):
    findings = await analyze_chain(session, request_ids=body.request_ids, last_n=body.last_n)
    result = [FindingOut.model_validate(f) for f in findings]
    await broadcast("new_chain_findings", [r.model_dump() for r in result])
    return result


# ─── Findings ────────────────────────────────────────────────

@router.get("/findings", response_model=list[FindingOut])
async def list_findings(
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    chain_only: bool = False,
    session: AsyncSession = Depends(get_session),
):
    stmt = select(Finding).order_by(desc(Finding.timestamp))
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if chain_only:
        stmt = stmt.where(Finding.is_chain == 1)
    stmt = stmt.offset(offset).limit(limit)
    result = await session.execute(stmt)
    return result.scalars().all()


@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: int, session: AsyncSession = Depends(get_session)):
    finding = await session.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


# ─── Simulation ──────────────────────────────────────────────

@router.post("/simulate", response_model=SimulationOut)
async def simulate(body: SimulationRequest, session: AsyncSession = Depends(get_session)):
    finding = await session.get(Finding, body.finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    sim = await run_simulation(session, body.finding_id)
    if not sim:
        raise HTTPException(status_code=500, detail="Simulation failed")
    result = SimulationOut.model_validate(sim)
    await broadcast("simulation_result", result.model_dump())
    return result


@router.get("/simulations", response_model=list[SimulationOut])
async def list_simulations(
    limit: int = 50,
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
):
    stmt = select(Simulation).order_by(desc(Simulation.timestamp)).offset(offset).limit(limit)
    result = await session.execute(stmt)
    return result.scalars().all()


# ─── Config ──────────────────────────────────────────────────

@router.get("/config/domains", response_model=DomainConfig)
async def get_domains():
    return DomainConfig(domains=settings.target_domains)


@router.put("/config/domains", response_model=DomainConfig)
async def update_domains(body: DomainConfig):
    settings.target_domains = body.domains
    from app.proxy.interceptor import configure_interceptor
    import asyncio
    configure_interceptor(
        api_base=f"http://{settings.api_host}:{settings.api_port}",
        target_domains=settings.target_domains,
        event_queue=None,
    )
    return body


# ─── Stats ───────────────────────────────────────────────────

@router.get("/stats", response_model=StatsOut)
async def get_stats(session: AsyncSession = Depends(get_session)):
    req_count = (await session.execute(select(func.count(CapturedRequest.id)))).scalar() or 0
    finding_count = (await session.execute(select(func.count(Finding.id)))).scalar() or 0
    sim_count = (await session.execute(select(func.count(Simulation.id)))).scalar() or 0

    severity_stmt = select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)
    sev_result = await session.execute(severity_stmt)
    severity_counts = {row[0].value if hasattr(row[0], "value") else row[0]: row[1] for row in sev_result}

    top_vuln_stmt = (
        select(Finding.vuln_type, func.count(Finding.id).label("cnt"))
        .group_by(Finding.vuln_type)
        .order_by(desc("cnt"))
        .limit(10)
    )
    top_result = await session.execute(top_vuln_stmt)
    top_vuln_types = [{"vuln_type": row[0], "count": row[1]} for row in top_result]

    return StatsOut(
        total_requests=req_count,
        total_findings=finding_count,
        total_simulations=sim_count,
        severity_counts=severity_counts,
        top_vuln_types=top_vuln_types,
    )


# ─── WebSocket ───────────────────────────────────────────────

@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    await subscribe(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await unsubscribe(ws)
