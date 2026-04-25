from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class CapturedRequestOut(BaseModel):
    id: int
    timestamp: datetime
    method: str
    url: str
    host: str
    path: str
    query_params: str
    request_headers: str
    request_body: str
    content_type: str
    status_code: Optional[int]
    response_headers: str
    response_body: str

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: int
    request_id: int
    timestamp: datetime
    vuln_type: str
    severity: str
    title: str
    description: str
    evidence: str
    recommendation: str
    cwe_id: str
    confidence: float
    cvss_score: float
    cvss_vector: str
    owasp_category: str
    attack_scenario: str
    false_positive_check: int
    pre_analysis_confidence: float
    is_chain: int
    chain_id: Optional[str]

    model_config = {"from_attributes": True}


class SimulationOut(BaseModel):
    id: int
    finding_id: int
    timestamp: datetime
    status: str
    attack_type: str
    payload: str
    raw_request: str
    raw_response: str
    result_summary: str
    verified: int

    model_config = {"from_attributes": True}


class SimulationRequest(BaseModel):
    finding_id: int


class AnalyzeRequest(BaseModel):
    request_id: int


class ChainAnalyzeRequest(BaseModel):
    request_ids: Optional[list[int]] = None
    last_n: Optional[int] = None


class DomainConfig(BaseModel):
    domains: list[str]


class StatsOut(BaseModel):
    total_requests: int
    total_findings: int
    total_simulations: int
    severity_counts: dict[str, int]
    top_vuln_types: list[dict[str, int | str]]
