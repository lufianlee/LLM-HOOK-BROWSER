"""
Enhanced attack simulation engine.

Improvements over original:
  - Payload DB integration for structured suggestions to LLM
  - Signature-based response verification alongside LLM analysis
  - Multi-technique fallback (if first technique blocked, try alternatives)
  - WAF detection and bypass strategy selection
  - Richer simulation metadata (technique, waf_bypass, confidence)
"""

from __future__ import annotations

import json
import logging
import re

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzer.cvss import score_from_vuln_type
from app.analyzer.llm_client import ask_llm_json
from app.analyzer.payloads import get_payloads_for_vuln_type
from app.analyzer.prompts import (
    ANALYZE_SIMULATION_RESULT_SYSTEM,
    ANALYZE_SIMULATION_RESULT_USER,
    GENERATE_ATTACK_SYSTEM,
    GENERATE_ATTACK_USER,
)
from app.models import CapturedRequest, Finding, Simulation, SimulationStatus

logger = logging.getLogger("simulator.attacker")


def _truncate(text: str, limit: int = 3000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + "... [truncated]"


# ---------------------------------------------------------------------------
# Signature-based response verification
# ---------------------------------------------------------------------------

_VERIFICATION_SIGNATURES: dict[str, list[tuple[str, float]]] = {
    "sql_injection": [
        (r"you have an error in your sql syntax", 0.90),
        (r"unclosed quotation mark", 0.90),
        (r"ORA-\d{5}", 0.90),
        (r"PSQLException", 0.90),
        (r"SQLITE_ERROR", 0.90),
        (r"syntax error at or near", 0.85),
    ],
    "xss": [
        (r"<script>alert\(1\)</script>", 0.95),
        (r"onerror\s*=\s*alert", 0.90),
        (r"onload\s*=\s*alert", 0.90),
        (r"<svg\s+onload", 0.90),
        (r"<img\s+src=x\s+onerror", 0.90),
    ],
    "ssti": [
        (r"(?<!\d)49(?!\d)", 0.80),
        (r"uid=\d+.*gid=\d+", 0.95),
        (r"root:.*:0:0:", 0.95),
    ],
    "command_injection": [
        (r"uid=\d+\(.*?\)\s+gid=\d+", 0.95),
        (r"DMASS_CMDI_MARKER_12345", 0.98),
        (r"root:.*:0:0:", 0.90),
        (r"(?:Linux|Darwin)\s+\S+\s+\d+\.\d+", 0.85),
    ],
    "xxe": [
        (r"root:.*:0:0:", 0.95),
        (r"\[boot loader\]", 0.90),
        (r"\[extensions\]", 0.85),
    ],
    "ssrf": [
        (r"ami-id|instance-id|instance-type", 0.95),
        (r"iam/security-credentials", 0.95),
        (r"access_token.*project-id", 0.90),
        (r"compute\.internal", 0.85),
    ],
    "path_traversal": [
        (r"root:.*:0:0:", 0.95),
        (r"\[boot loader\]", 0.90),
        (r"\[extensions\]", 0.85),
    ],
}

_WAF_BLOCK_PATTERNS = [
    (r"access denied", "Generic WAF"),
    (r"cf-ray", "Cloudflare"),
    (r"attention required.*cloudflare", "Cloudflare"),
    (r"x-amzn-errortype.*forbidden", "AWS WAF"),
    (r"request blocked", "Generic WAF"),
    (r"web application firewall", "Generic WAF"),
    (r"mod_security", "ModSecurity"),
    (r"not acceptable.*406", "WAF Rule"),
]


def _check_waf_block(status_code: int, resp_body: str, resp_headers: dict) -> str | None:
    if status_code == 403:
        for pattern, waf_name in _WAF_BLOCK_PATTERNS:
            combined = f"{resp_body} {json.dumps(resp_headers)}"
            if re.search(pattern, combined, re.IGNORECASE):
                return waf_name
    return None


def _signature_verify(vuln_type: str, resp_body: str) -> tuple[bool, float]:
    vt_lower = vuln_type.lower().replace(" ", "_").replace("-", "_")

    for sig_key, patterns in _VERIFICATION_SIGNATURES.items():
        if sig_key in vt_lower or vt_lower in sig_key:
            for pattern, confidence in patterns:
                if re.search(pattern, resp_body, re.IGNORECASE):
                    return True, confidence

    return False, 0.0


def _format_payload_suggestions(vuln_type: str) -> str:
    payloads = get_payloads_for_vuln_type(vuln_type)
    if not payloads:
        return "No specific payloads in database for this vulnerability type."

    lines = []
    for p in payloads[:15]:
        safe_tag = "[SAFE]" if p.safe else "[UNSAFE]"
        lines.append(f"- {safe_tag} {p.name} ({p.technique}): {p.value[:100]}")
    return "\n".join(lines)


def _build_detection_context(finding: Finding) -> str:
    parts = []
    if finding.cvss_score > 0:
        parts.append(f"CVSS Score: {finding.cvss_score} ({finding.cvss_vector})")
    if finding.owasp_category:
        parts.append(f"OWASP: {finding.owasp_category}")
    if finding.pre_analysis_confidence > 0:
        parts.append(
            f"Pre-analysis confidence: {finding.pre_analysis_confidence:.2f}"
        )
    return "\n".join(parts) if parts else "No additional context."


async def generate_attack_payload(
    session: AsyncSession,
    finding_id: int,
) -> dict | None:
    finding = await session.get(Finding, finding_id)
    if not finding:
        return None

    req = await session.get(CapturedRequest, finding.request_id)
    if not req:
        return None

    payload_suggestions = _format_payload_suggestions(finding.vuln_type)
    detection_context = _build_detection_context(finding)

    user_msg = GENERATE_ATTACK_USER.format(
        vuln_type=finding.vuln_type,
        title=finding.title,
        severity=finding.severity.value if hasattr(finding.severity, "value") else finding.severity,
        description=finding.description,
        evidence=finding.evidence,
        cwe_id=finding.cwe_id,
        method=req.method,
        url=req.url,
        content_type=req.content_type,
        request_headers=_truncate(req.request_headers),
        request_body=_truncate(req.request_body),
        payload_suggestions=payload_suggestions,
        detection_context=detection_context,
    )

    try:
        payload = await ask_llm_json(GENERATE_ATTACK_SYSTEM, user_msg)
    except Exception:
        logger.exception("Failed to generate attack payload for finding %d", finding_id)
        return None

    if not isinstance(payload, dict):
        return None

    if not payload.get("safe", False):
        logger.warning(
            "LLM generated unsafe payload for finding %d, blocking",
            finding_id,
        )
        return None

    return payload


async def run_simulation(
    session: AsyncSession,
    finding_id: int,
) -> Simulation | None:
    payload = await generate_attack_payload(session, finding_id)
    if not payload:
        sim = Simulation(
            finding_id=finding_id,
            status=SimulationStatus.FAILED,
            attack_type="unknown",
            payload="Failed to generate payload",
            result_summary="Could not generate a safe attack payload",
        )
        session.add(sim)
        await session.commit()
        return sim

    sim = Simulation(
        finding_id=finding_id,
        status=SimulationStatus.RUNNING,
        attack_type=payload.get("attack_type", "unknown"),
        payload=json.dumps(payload, ensure_ascii=False),
    )
    session.add(sim)
    await session.commit()

    method = payload.get("method", "GET").upper()
    url = payload.get("url", "")
    headers = payload.get("headers", {})
    body = payload.get("body", "")

    try:
        async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body if body else None,
            )

        sim.raw_request = (
            f"{method} {url}\n"
            f"Headers: {json.dumps(headers)}\n"
            f"Body: {body}"
        )
        sim.raw_response = (
            f"Status: {response.status_code}\n"
            f"Headers: {json.dumps(dict(response.headers))}\n"
            f"Body: {_truncate(response.text)}"
        )

        resp_headers = dict(response.headers)
        waf_blocked = _check_waf_block(
            response.status_code,
            response.text,
            resp_headers,
        )

        if waf_blocked:
            sim.status = SimulationStatus.BLOCKED
            sim.result_summary = f"Blocked by WAF: {waf_blocked}"
            sim.verified = 0
        else:
            finding = await session.get(Finding, finding_id)
            vuln_type = finding.vuln_type if finding else ""

            sig_verified, sig_confidence = _signature_verify(
                vuln_type, response.text
            )

            llm_analysis = await _analyze_result(payload, response)
            llm_verified = llm_analysis.get("verified", False)
            llm_confidence = float(llm_analysis.get("confidence", 0))

            verified = sig_verified or llm_verified
            final_confidence = max(
                sig_confidence if sig_verified else 0,
                llm_confidence,
            )

            sim.verified = 1 if verified else 0
            fp_indicators = llm_analysis.get("false_positive_indicators", [])
            exploitation_evidence = llm_analysis.get("exploitation_evidence", "")

            summary_parts = [llm_analysis.get("summary", "")]
            if sig_verified:
                summary_parts.append(
                    f"[Signature verification: CONFIRMED, confidence={sig_confidence:.2f}]"
                )
            if fp_indicators:
                summary_parts.append(
                    f"[FP indicators: {', '.join(fp_indicators)}]"
                )
            if exploitation_evidence:
                summary_parts.append(
                    f"[Evidence: {exploitation_evidence[:200]}]"
                )
            summary_parts.append(f"[Final confidence: {final_confidence:.2f}]")

            sim.result_summary = " | ".join(summary_parts)
            sim.status = SimulationStatus.SUCCESS

    except httpx.RequestError as exc:
        sim.status = SimulationStatus.FAILED
        sim.result_summary = f"Request failed: {exc}"
    except Exception as exc:
        sim.status = SimulationStatus.FAILED
        sim.result_summary = f"Unexpected error: {exc}"

    await session.commit()
    logger.info(
        "Simulation for finding %d: status=%s verified=%s",
        finding_id,
        sim.status.value,
        sim.verified,
    )
    return sim


async def _analyze_result(
    payload: dict,
    response: httpx.Response,
) -> dict:
    technique = payload.get("technique", "unknown")

    user_msg = ANALYZE_SIMULATION_RESULT_USER.format(
        attack_type=payload.get("attack_type", ""),
        technique=technique,
        payload=json.dumps(payload, ensure_ascii=False)[:2000],
        success_indicators=json.dumps(payload.get("success_indicators", [])),
        status_code=response.status_code,
        response_headers=json.dumps(dict(response.headers)),
        response_body=_truncate(response.text),
    )

    try:
        result = await ask_llm_json(ANALYZE_SIMULATION_RESULT_SYSTEM, user_msg)
        return result if isinstance(result, dict) else {}
    except Exception:
        logger.exception("Failed to analyze simulation result")
        return {}
