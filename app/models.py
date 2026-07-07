from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SimulationStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"


class CapturedRequest(Base):
    __tablename__ = "captured_requests"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    method = Column(String(10), nullable=False, index=True)
    url = Column(Text, nullable=False)
    host = Column(String(255), nullable=False, index=True)
    path = Column(Text, nullable=False)
    query_params = Column(Text, default="")
    request_headers = Column(Text, default="{}")
    request_body = Column(Text, default="")
    content_type = Column(String(255), default="")
    status_code = Column(Integer, nullable=True)
    response_headers = Column(Text, default="{}")
    response_body = Column(Text, default="")

    findings = relationship("Finding", back_populates="request", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(Integer, ForeignKey("captured_requests.id"), nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    vuln_type = Column(String(100), nullable=False)
    severity = Column(Enum(Severity), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(Text, default="")
    recommendation = Column(Text, default="")
    cwe_id = Column(String(20), default="")
    confidence = Column(Float, default=0.0)
    cvss_score = Column(Float, default=0.0)
    cvss_vector = Column(String(200), default="")
    owasp_category = Column(String(100), default="")
    attack_scenario = Column(Text, default="")
    false_positive_check = Column(Integer, default=0)
    pre_analysis_confidence = Column(Float, default=0.0)
    is_chain = Column(Integer, default=0, index=True)
    chain_id = Column(String(100), nullable=True)

    request = relationship("CapturedRequest", back_populates="findings")
    simulations = relationship("Simulation", back_populates="finding", cascade="all, delete-orphan")


class Simulation(Base):
    __tablename__ = "simulations"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    status = Column(Enum(SimulationStatus), default=SimulationStatus.PENDING)
    attack_type = Column(String(100), nullable=False)
    payload = Column(Text, nullable=False)
    raw_request = Column(Text, default="")
    raw_response = Column(Text, default="")
    result_summary = Column(Text, default="")
    verified = Column(Integer, default=0)

    finding = relationship("Finding", back_populates="simulations")
