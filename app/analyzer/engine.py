"""
Two-stage vulnerability analysis engine.

Stage 1: Algorithmic pre-analysis (pattern matching, signature detection)
Stage 2: LLM deep analysis (with pre-analysis hints injected into prompt)

Post-processing: CVSS scoring, confidence merging, deduplication.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzer.cvss import score_from_vuln_type
from app.analyzer.llm_client import ask_llm_json
from app.analyzer.pre_analyzer import run_pre_analysis, PreAnalysisResult
from app.analyzer.prompts import (
    CHAIN_ANALYSIS_SYSTEM,
    CHAIN_ANALYSIS_USER,
    SINGLE_REQUEST_SYSTEM,
    SINGLE_REQUEST_USER,
)
from app.config import settings
from app.models import CapturedRequest, Finding, Severity

logger = logging.getLogger("analyzer.engine")


def _truncate(text: str, limit: int = 3000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n... [truncated, {len(text)} chars total]"


def _severity_from_str(s: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get(s.lower(), Severity.INFO)


def _merge_confidence(llm_confidence: float, pre_confidence: float) -> float:
    if pre_confidence <= 0:
        return llm_confidence
    if llm_confidence <= 0:
        return pre_confidence
    merged = 1 - (1 - llm_confidence) * (1 - pre_confidence)
    return round(min(merged, 1.0), 3)


def _find_pre_hint_confidence(
    pre_result: PreAnalysisResult,
    vuln_type: str,
) -> float:
    vt_lower = vuln_type.lower()
    best = 0.0
    for hint in pre_result.hints:
        if (
            hint.category.lower() in vt_lower
            or vt_lower in hint.category.lower()
        ):
            best = max(best, hint.confidence)
    return best


async def analyze_single_request(
    session: AsyncSession,
    request_id: int,
) -> list[Finding]:
    req = await session.get(CapturedRequest, request_id)
    if not req:
        logger.warning("Request %d not found", request_id)
        return []

    # --- Stage 1: Algorithmic pre-analysis ---
    # Runs ~150 regexes over response bodies up to 50 KB (several ms of pure
    # CPU). Offload to a thread so it does not block the event loop that is
    # simultaneously draining the proxy capture queue and serving websockets.
    pre_result = await asyncio.to_thread(
        run_pre_analysis,
        method=req.method,
        url=req.url,
        content_type=req.content_type,
        request_headers=req.request_headers,
        request_body=req.request_body,
        status_code=req.status_code,
        response_headers=req.response_headers,
        response_body=req.response_body,
        query_params=req.query_params,
    )

    pre_hints_text = pre_result.to_prompt_section()

    # --- Stage 2: LLM deep analysis (with hints) ---
    user_msg = SINGLE_REQUEST_USER.format(
        method=req.method,
        url=req.url,
        content_type=req.content_type,
        request_headers=_truncate(req.request_headers),
        request_body=_truncate(req.request_body),
        status_code=req.status_code,
        response_headers=_truncate(req.response_headers),
        response_body=_truncate(req.response_body),
        pre_analysis_hints=pre_hints_text,
    )

    try:
        results = await ask_llm_json(SINGLE_REQUEST_SYSTEM, user_msg)
    except Exception:
        logger.exception("LLM analysis failed for request %d", request_id)
        results = []

    if not isinstance(results, list):
        results = [results] if results else []

    # --- Post-processing: CVSS, confidence merge, dedup ---
    findings = []
    seen_types: set[str] = set()

    for r in results:
        if not isinstance(r, dict):
            continue

        llm_confidence = float(r.get("confidence", 0))
        if llm_confidence < 0.3:
            continue

        vuln_type = r.get("vuln_type", "unknown")
        dedup_key = f"{vuln_type}:{r.get('cwe_id', '')}"
        if dedup_key in seen_types:
            continue
        seen_types.add(dedup_key)

        pre_confidence = _find_pre_hint_confidence(pre_result, vuln_type)
        merged_confidence = _merge_confidence(llm_confidence, pre_confidence)

        cvss_vector = r.get("cvss_vector", "")
        cvss = score_from_vuln_type(vuln_type, cvss_vector)

        severity_str = r.get("severity", "info")
        if cvss.score >= 9.0:
            severity_str = "critical"
        elif cvss.score >= 7.0 and severity_str in ("medium", "low", "info"):
            severity_str = "high"

        finding = Finding(
            request_id=request_id,
            vuln_type=vuln_type,
            severity=_severity_from_str(severity_str),
            title=r.get("title", ""),
            description=r.get("description", ""),
            evidence=r.get("evidence", ""),
            recommendation=r.get("recommendation", ""),
            cwe_id=r.get("cwe_id", ""),
            confidence=merged_confidence,
            cvss_score=cvss.score,
            cvss_vector=cvss.vector,
            owasp_category=r.get("owasp_category", ""),
            attack_scenario=r.get("attack_scenario", ""),
            pre_analysis_confidence=pre_confidence,
            is_chain=0,
        )
        session.add(finding)
        findings.append(finding)

    # --- Add high-confidence pre-analysis findings not covered by LLM ---
    for hint in pre_result.hints:
        if hint.confidence >= 0.75:
            dedup_key = f"{hint.category}:{hint.cwe_id}"
            if dedup_key not in seen_types:
                seen_types.add(dedup_key)
                cvss = score_from_vuln_type(hint.category)
                finding = Finding(
                    request_id=request_id,
                    vuln_type=hint.category,
                    severity=_severity_from_str(hint.severity_suggestion),
                    title=f"[Pre-Analysis] {hint.indicator}",
                    description=hint.evidence,
                    evidence=hint.evidence,
                    recommendation="Verify manually and apply appropriate remediation.",
                    cwe_id=hint.cwe_id,
                    confidence=hint.confidence,
                    cvss_score=cvss.score,
                    cvss_vector=cvss.vector,
                    owasp_category=hint.owasp,
                    pre_analysis_confidence=hint.confidence,
                    is_chain=0,
                )
                session.add(finding)
                findings.append(finding)

    # --- Security headers as info findings ---
    if pre_result.security_headers_missing:
        cvss = score_from_vuln_type("missing_security_headers")
        finding = Finding(
            request_id=request_id,
            vuln_type="Missing Security Headers",
            severity=Severity.INFO,
            title="Security headers missing",
            description="\n".join(pre_result.security_headers_missing),
            evidence="\n".join(pre_result.security_headers_missing),
            recommendation="Add all recommended security headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.",
            cwe_id="CWE-693",
            confidence=0.90,
            cvss_score=cvss.score,
            cvss_vector=cvss.vector,
            owasp_category="A05:2021-Security Misconfiguration",
            pre_analysis_confidence=0.90,
            is_chain=0,
        )
        session.add(finding)
        findings.append(finding)

    await session.commit()
    logger.info(
        "Found %d vulnerabilities in request %d (pre-analysis: %d hints)",
        len(findings),
        request_id,
        len(pre_result.hints),
    )
    return findings


async def analyze_chain(
    session: AsyncSession,
    request_ids: Optional[list[int]] = None,
    last_n: Optional[int] = None,
) -> list[Finding]:
    if request_ids:
        stmt = (
            select(CapturedRequest)
            .where(CapturedRequest.id.in_(request_ids))
            .order_by(CapturedRequest.timestamp)
        )
    elif last_n:
        stmt = (
            select(CapturedRequest)
            .order_by(CapturedRequest.timestamp.desc())
            .limit(last_n)
        )
    else:
        stmt = (
            select(CapturedRequest)
            .order_by(CapturedRequest.timestamp.desc())
            .limit(settings.max_history_for_chain)
        )

    result = await session.execute(stmt)
    requests = list(result.scalars().all())

    if last_n or (not request_ids):
        requests.reverse()

    if len(requests) < 2:
        logger.info("Not enough requests for chain analysis")
        return []

    # --- Run pre-analysis on each request for summary ---
    # Offloaded to threads and gathered so a chain over many requests does not
    # block the event loop (each pre-analysis is several ms of CPU).
    pre_results = await asyncio.gather(
        *(
            asyncio.to_thread(
                run_pre_analysis,
                method=req.method,
                url=req.url,
                content_type=req.content_type,
                request_headers=req.request_headers,
                request_body=req.request_body,
                status_code=req.status_code,
                response_headers=req.response_headers,
                response_body=req.response_body,
                query_params=req.query_params,
            )
            for req in requests
        )
    )
    all_pre_hints: list[str] = []
    for req, pre in zip(requests, pre_results):
        for hint in pre.hints:
            all_pre_hints.append(
                f"- Request {req.id}: [{hint.category}] {hint.indicator} "
                f"(confidence={hint.confidence:.2f})"
            )

    pre_summary = ""
    if all_pre_hints:
        pre_summary = (
            "## Pre-Analysis Summary (per-request algorithmic findings)\n"
            + "\n".join(all_pre_hints[:30])
        )

    transactions = []
    for req in requests:
        transactions.append(
            f"### Request ID: {req.id}\n"
            f"- Method: {req.method}\n"
            f"- URL: {req.url}\n"
            f"- Content-Type: {req.content_type}\n"
            f"- Request Headers: {_truncate(req.request_headers, 500)}\n"
            f"- Request Body: {_truncate(req.request_body, 1000)}\n"
            f"- Status: {req.status_code}\n"
            f"- Response Headers: {_truncate(req.response_headers, 500)}\n"
            f"- Response Body: {_truncate(req.response_body, 1000)}\n"
        )

    user_msg = CHAIN_ANALYSIS_USER.format(
        count=len(requests),
        transactions="\n---\n".join(transactions),
        pre_analysis_summary=pre_summary,
    )

    try:
        results = await ask_llm_json(CHAIN_ANALYSIS_SYSTEM, user_msg)
    except Exception:
        logger.exception("Chain analysis LLM call failed")
        return []

    if not isinstance(results, list):
        results = [results] if results else []

    findings = []
    for r in results:
        if not isinstance(r, dict):
            continue
        confidence = float(r.get("confidence", 0))
        if confidence < 0.3:
            continue

        involved_ids = r.get("involved_request_ids", [])
        primary_request_id = involved_ids[0] if involved_ids else requests[0].id

        vuln_type = r.get("vuln_type", "chain_attack")
        cvss_vector = r.get("cvss_vector", "")
        cvss = score_from_vuln_type(vuln_type, cvss_vector)

        finding = Finding(
            request_id=primary_request_id,
            vuln_type=vuln_type,
            severity=_severity_from_str(r.get("severity", "info")),
            title=r.get("title", ""),
            description=r.get("description", ""),
            evidence=r.get("evidence", ""),
            recommendation=r.get("recommendation", ""),
            cwe_id=r.get("cwe_id", ""),
            confidence=confidence,
            cvss_score=cvss.score,
            cvss_vector=cvss.vector,
            owasp_category=r.get("owasp_category", ""),
            attack_scenario=r.get("attack_scenario", ""),
            is_chain=1,
            chain_id=r.get("chain_id", ""),
        )
        session.add(finding)
        findings.append(finding)

    await session.commit()
    logger.info("Chain analysis found %d potential attack chains", len(findings))
    return findings
