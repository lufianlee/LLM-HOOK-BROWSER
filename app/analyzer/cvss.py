"""
CVSS v3.1 Base Score calculator.

Implements the exact CVSS v3.1 specification formula, plus a mapping from
common vulnerability types to default CVSS vectors (used when the LLM
doesn't return a vector string).

Referenced from dmass reporter/cvss-calculator.ts.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass
class CVSSResult:
    score: float
    severity: str
    vector: str


# ---------------------------------------------------------------------------
# Metric weights per CVSS v3.1 specification
# ---------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_S_VALUES = {"U", "C"}


def _roundup(x: float) -> float:
    return math.ceil(x * 10) / 10


def calculate_cvss(vector: str) -> CVSSResult:
    metrics: dict[str, str] = {}
    parts = vector.replace("CVSS:3.1/", "").split("/")
    for part in parts:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v

    av = _AV.get(metrics.get("AV", "N"), 0.85)
    ac = _AC.get(metrics.get("AC", "L"), 0.77)
    scope = metrics.get("S", "U")
    pr_map = _PR_CHANGED if scope == "C" else _PR_UNCHANGED
    pr = pr_map.get(metrics.get("PR", "N"), 0.85)
    ui = _UI.get(metrics.get("UI", "N"), 0.85)

    c = _CIA.get(metrics.get("C", "N"), 0.0)
    i = _CIA.get(metrics.get("I", "N"), 0.0)
    a = _CIA.get(metrics.get("A", "N"), 0.0)

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    elif scope == "U":
        base_score = _roundup(min(impact + exploitability, 10))
    else:
        base_score = _roundup(min(1.08 * (impact + exploitability), 10))

    if base_score >= 9.0:
        severity = "critical"
    elif base_score >= 7.0:
        severity = "high"
    elif base_score >= 4.0:
        severity = "medium"
    elif base_score > 0:
        severity = "low"
    else:
        severity = "info"

    return CVSSResult(score=base_score, severity=severity, vector=vector)


# ---------------------------------------------------------------------------
# Default CVSS vectors per vulnerability type
# ---------------------------------------------------------------------------

_DEFAULT_VECTORS: dict[str, str] = {
    "sql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "sqli": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "nosql_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "reflected_xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "stored_xss": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
    "dom_xss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "ssti": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "command_injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cmdi": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "xxe": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
    "ssrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    "idor": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "bfla": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    "bola": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "mass_assignment": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "path_traversal": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "http_smuggling": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
    "cors_misconfiguration": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
    "csrf": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    "jwt": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "open_redirect": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "deserialization": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "sensitive_data_exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "information_disclosure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "insecure_cookie": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "missing_security_headers": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "graphql_introspection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    "race_condition": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
    "authentication_bypass": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "privilege_escalation": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "session_fixation": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    "file_upload": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "business_logic": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
}


def _normalize_vuln_type(vuln_type: str) -> str:
    normalized = re.sub(r"[^a-z0-9]", "_", vuln_type.lower().strip())
    normalized = re.sub(r"_+", "_", normalized).strip("_")
    return normalized


def get_default_cvss(vuln_type: str) -> CVSSResult | None:
    normalized = _normalize_vuln_type(vuln_type)

    if normalized in _DEFAULT_VECTORS:
        return calculate_cvss(_DEFAULT_VECTORS[normalized])

    for key, vector in _DEFAULT_VECTORS.items():
        if key in normalized or normalized in key:
            return calculate_cvss(vector)

    return None


def score_from_vuln_type(vuln_type: str, cvss_vector: str = "") -> CVSSResult:
    if cvss_vector and cvss_vector.startswith("CVSS:"):
        try:
            return calculate_cvss(cvss_vector)
        except Exception:
            pass

    result = get_default_cvss(vuln_type)
    if result:
        return result

    return CVSSResult(score=0.0, severity="info", vector="")
