"""
Algorithmic pre-analysis engine.

Runs pattern matching, signature detection, and heuristic checks BEFORE
the LLM call.  Results feed into the LLM prompt as structured hints so the
model can focus on confirmation and deeper reasoning rather than surface-
level pattern scanning.

Detection techniques referenced from:
  - dmass (sqli-detector, nosql-detector, ssti-detector, cmdi-detector,
    xxe-detector, smuggling-detector, xss payload-generator,
    jwt-auditor, path-traversal-detector, mass-assignment-detector,
    secrets-scanner, waf-detector, cloud-metadata-prober)
  - OWASP ZAP passive scan rules
  - Burp Suite passive scanner heuristics
  - Nuclei template signatures
  - SQLMap error signatures
  - Dalfox XSS context analysis
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, unquote_plus, urlparse

logger = logging.getLogger("analyzer.pre_analyzer")


@dataclass
class Hint:
    category: str
    indicator: str
    evidence: str
    confidence: float
    cwe_id: str = ""
    severity_suggestion: str = "medium"
    owasp: str = ""


@dataclass
class PreAnalysisResult:
    hints: list[Hint] = field(default_factory=list)
    detected_tech: list[str] = field(default_factory=list)
    waf_detected: str = ""
    security_headers_missing: list[str] = field(default_factory=list)

    def to_prompt_section(self) -> str:
        if not self.hints and not self.security_headers_missing and not self.detected_tech:
            return ""

        parts = ["## Pre-Analysis Hints (algorithmic detection — verify before reporting)"]

        if self.detected_tech:
            parts.append(f"**Detected Technologies:** {', '.join(self.detected_tech)}")
        if self.waf_detected:
            parts.append(f"**WAF Detected:** {self.waf_detected}")
        if self.security_headers_missing:
            parts.append(
                f"**Missing Security Headers:** {', '.join(self.security_headers_missing)}"
            )

        for h in self.hints:
            parts.append(
                f"- [{h.category}] (confidence={h.confidence:.2f}, "
                f"severity_hint={h.severity_suggestion}, cwe={h.cwe_id}, owasp={h.owasp})\n"
                f"  Indicator: {h.indicator}\n"
                f"  Evidence: {h.evidence[:500]}"
            )

        return "\n".join(parts)


# ---------------------------------------------------------------------------
# SQL Injection signatures (SQLMap + dmass sqli-detector)
# ---------------------------------------------------------------------------

_SQLI_ERROR_PATTERNS: list[tuple[str, str]] = [
    (r"you have an error in your sql syntax", "MySQL"),
    (r"warning:.*mysql_", "MySQL"),
    (r"MySQLSyntaxErrorException", "MySQL"),
    (r"com\.mysql\.jdbc", "MySQL"),
    (r"unclosed quotation mark after the character string", "MSSQL"),
    (r"incorrect syntax near", "MSSQL"),
    (r"microsoft sql native client error", "MSSQL"),
    (r"mssql_query\(\)", "MSSQL"),
    (r"\[Microsoft\]\[ODBC SQL Server Driver\]", "MSSQL"),
    (r"ORA-\d{5}", "Oracle"),
    (r"oracle\.jdbc\.driver", "Oracle"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"PSQLException", "PostgreSQL"),
    (r"syntax error at or near", "PostgreSQL"),
    (r"pg_query\(\)", "PostgreSQL"),
    (r"unterminated quoted string at or near", "PostgreSQL"),
    (r"SQLite3::SQLException", "SQLite"),
    (r"SQLITE_ERROR", "SQLite"),
    (r"unrecognized token", "SQLite"),
    (r"near \".*\": syntax error", "SQLite"),
    (r"SQL syntax.*MySQL", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"Dynamic SQL Error", "Firebird"),
    (r"pg_exec\(\)", "PostgreSQL"),
]

_SQLI_PAYLOAD_PATTERNS = [
    r"(?:'|\")?\s*(?:OR|AND)\s+(?:'?\d+'?\s*=\s*'?\d+'?|true|1)",
    r"(?:UNION\s+(?:ALL\s+)?SELECT)",
    r"(?:SELECT\s+.*\s+FROM\s+)",
    r"(?:INSERT\s+INTO|UPDATE\s+.*\s+SET|DELETE\s+FROM)",
    r"(?:DROP\s+(?:TABLE|DATABASE))",
    r"(?:--|#|/\*)\s*$",
    r"(?:SLEEP|WAITFOR\s+DELAY|BENCHMARK|PG_SLEEP)\s*\(",
    r"(?:LOAD_FILE|INTO\s+(?:OUT|DUMP)FILE)",
    r"(?:CHAR|CONCAT|GROUP_CONCAT)\s*\(",
    r"(?:information_schema|sys\.tables|sysobjects|pg_catalog)",
]


def _check_sqli(
    url: str,
    req_body: str,
    resp_body: str,
    query_params: str,
) -> list[Hint]:
    hints: list[Hint] = []
    combined_input = f"{url} {req_body} {query_params}"

    for pattern, dbms in _SQLI_ERROR_PATTERNS:
        if re.search(pattern, resp_body, re.IGNORECASE):
            hints.append(Hint(
                category="SQL Injection",
                indicator=f"Database error signature detected ({dbms})",
                evidence=f"Pattern: {pattern}",
                confidence=0.85,
                cwe_id="CWE-89",
                severity_suggestion="high",
                owasp="A03:2021-Injection",
            ))
            break

    for pattern in _SQLI_PAYLOAD_PATTERNS:
        if re.search(pattern, combined_input, re.IGNORECASE):
            hints.append(Hint(
                category="SQL Injection",
                indicator="SQL injection payload detected in request",
                evidence=f"Pattern matched: {pattern}",
                confidence=0.70,
                cwe_id="CWE-89",
                severity_suggestion="high",
                owasp="A03:2021-Injection",
            ))
            break

    return hints


# ---------------------------------------------------------------------------
# NoSQL Injection (dmass nosql-detector + MongoDB docs)
# ---------------------------------------------------------------------------

_NOSQL_PATTERNS = [
    r"\$(?:gt|gte|lt|lte|ne|eq|in|nin|exists|regex|where|or|and|not|nor|elemMatch)\b",
    r"\{\s*\"\$(?:gt|ne|regex|where|exists|in)",
    r"(?:this\.password|this\.username|function\s*\()",
    r"db\.(?:collection|runCommand|adminCommand)",
    r"(?:sleep|tojson|tojsononeline)\s*\(",
]

_NOSQL_ERROR_PATTERNS = [
    r"MongoError",
    r"CastError",
    r"BSONTypeError",
    r"E11000 duplicate key",
    r"Cannot apply \$\w+ to",
]


def _check_nosql(
    req_body: str,
    resp_body: str,
    query_params: str,
    content_type: str,
) -> list[Hint]:
    hints: list[Hint] = []
    combined_input = f"{req_body} {query_params}"

    for pattern in _NOSQL_ERROR_PATTERNS:
        if re.search(pattern, resp_body, re.IGNORECASE):
            hints.append(Hint(
                category="NoSQL Injection",
                indicator="NoSQL/MongoDB error in response",
                evidence=f"Pattern: {pattern}",
                confidence=0.80,
                cwe_id="CWE-943",
                severity_suggestion="high",
                owasp="A03:2021-Injection",
            ))
            break

    for pattern in _NOSQL_PATTERNS:
        if re.search(pattern, combined_input, re.IGNORECASE):
            hints.append(Hint(
                category="NoSQL Injection",
                indicator="NoSQL operator/payload in request",
                evidence=f"Pattern matched: {pattern}",
                confidence=0.65,
                cwe_id="CWE-943",
                severity_suggestion="high",
                owasp="A03:2021-Injection",
            ))
            break

    return hints


# ---------------------------------------------------------------------------
# XSS Detection (Dalfox context analysis + dmass payload-generator)
# ---------------------------------------------------------------------------

_XSS_REFLECTED_PATTERNS = [
    r"<script[^>]*>",
    r"on(?:error|load|click|mouseover|focus|blur|change|submit|input)\s*=",
    r"javascript\s*:",
    r"<(?:img|svg|iframe|object|embed|video|audio|source|math|details|marquee)\b[^>]*\bon\w+\s*=",
    r"<(?:img|svg)\b[^>]*\bsrc\s*=\s*[\"']?(?:javascript|data):",
    r"expression\s*\(",
    r"url\s*\(\s*[\"']?javascript:",
    r"<\s*(?:a|area)\s[^>]*href\s*=\s*[\"']?javascript:",
]

_XSS_SINK_PATTERNS_IN_RESPONSE = [
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"document\.write\s*\(",
    r"eval\s*\(",
    r"setTimeout\s*\(\s*[\"']",
    r"setInterval\s*\(\s*[\"']",
    r"Function\s*\(",
    r"dangerouslySetInnerHTML",
    r"v-html\s*=",
    r"\$\{.*\}",  # template literals in script context
]


def _check_xss(
    url: str,
    req_body: str,
    resp_body: str,
    query_params: str,
    req_headers: dict,
) -> list[Hint]:
    hints: list[Hint] = []
    combined_input = f"{url} {req_body} {query_params}"

    all_params = _extract_all_params(url, req_body, query_params)
    for pval in all_params:
        if len(pval) > 3 and pval in resp_body:
            for pattern in _XSS_REFLECTED_PATTERNS:
                if re.search(pattern, pval, re.IGNORECASE):
                    hints.append(Hint(
                        category="Reflected XSS",
                        indicator="Input value with XSS payload reflected in response",
                        evidence=f"Value '{pval[:100]}' reflected; matched pattern: {pattern}",
                        confidence=0.80,
                        cwe_id="CWE-79",
                        severity_suggestion="high",
                        owasp="A03:2021-Injection",
                    ))
                    break

    for pattern in _XSS_REFLECTED_PATTERNS:
        if re.search(pattern, combined_input, re.IGNORECASE):
            hints.append(Hint(
                category="XSS Payload in Request",
                indicator="XSS payload pattern detected in request parameters",
                evidence=f"Pattern: {pattern}",
                confidence=0.60,
                cwe_id="CWE-79",
                severity_suggestion="medium",
                owasp="A03:2021-Injection",
            ))
            break

    for pattern in _XSS_SINK_PATTERNS_IN_RESPONSE:
        if re.search(pattern, resp_body, re.IGNORECASE):
            hints.append(Hint(
                category="DOM XSS Sink",
                indicator="Potentially dangerous DOM sink in response JavaScript",
                evidence=f"Pattern: {pattern}",
                confidence=0.45,
                cwe_id="CWE-79",
                severity_suggestion="medium",
                owasp="A03:2021-Injection",
            ))
            break

    return hints


# ---------------------------------------------------------------------------
# SSTI Detection (dmass ssti-detector engine fingerprints)
# ---------------------------------------------------------------------------

_SSTI_PROBES_IN_REQUEST = [
    (r"\{\{.*?\}\}", "Jinja2/Twig/Angular"),
    (r"\$\{.*?\}", "Freemarker/Spring EL/Java EL"),
    (r"#\{.*?\}", "Spring EL/Thymeleaf"),
    (r"<%=.*?%>", "ERB/JSP"),
    (r"\{\%.*?\%\}", "Jinja2/Django"),
    (r"#set\s*\(", "Velocity"),
    (r"T\(java\.lang", "Spring EL"),
    (r"__class__\.__mro__", "Python Jinja2"),
    (r"config\.__class__", "Python Jinja2"),
    (r"lipsum\.__globals__", "Python Jinja2"),
    (r"cycler\.__init__", "Python Jinja2"),
]

_SSTI_COMPUTED_RESULTS = [
    r"(?<!\d)49(?!\d)",  # 7*7
    r"(?<!\d)7777777(?!\d)",  # 7*'7' (Twig)
    r"uid=\d+.*gid=\d+",  # id command output (RCE)
    r"root:.*:0:0:",  # /etc/passwd (RCE)
]


def _check_ssti(
    req_body: str,
    resp_body: str,
    query_params: str,
) -> list[Hint]:
    hints: list[Hint] = []
    combined_input = f"{req_body} {query_params}"

    has_probe_in_request = False
    for pattern, engine in _SSTI_PROBES_IN_REQUEST:
        if re.search(pattern, combined_input):
            has_probe_in_request = True
            hints.append(Hint(
                category="SSTI",
                indicator=f"Template expression detected in input (possible engine: {engine})",
                evidence=f"Pattern: {pattern}",
                confidence=0.55,
                cwe_id="CWE-1336",
                severity_suggestion="critical",
                owasp="A03:2021-Injection",
            ))
            break

    if has_probe_in_request:
        for pattern in _SSTI_COMPUTED_RESULTS:
            if re.search(pattern, resp_body):
                hints.append(Hint(
                    category="SSTI",
                    indicator="Template computation result or RCE output in response",
                    evidence=f"Pattern: {pattern}",
                    confidence=0.75,
                    cwe_id="CWE-1336",
                    severity_suggestion="critical",
                    owasp="A03:2021-Injection",
                ))
                break

    return hints


# ---------------------------------------------------------------------------
# Command Injection (dmass cmdi-detector)
# ---------------------------------------------------------------------------

_CMDI_PATTERNS = [
    r"[;|&`]\s*(?:cat|ls|id|whoami|uname|pwd|echo|sleep|ping|nslookup|curl|wget|nc)\b",
    r"\$\((?:cat|ls|id|whoami|uname|pwd|echo|sleep|curl|wget)\b",
    r"`(?:cat|ls|id|whoami|uname|pwd|echo|sleep|curl|wget)\b",
    r"\|\|\s*(?:cat|ls|id|whoami|sleep)\b",
    r"&&\s*(?:cat|ls|id|whoami|sleep)\b",
    r"%0a(?:cat|ls|id|whoami)",
    r"\b(?:os\.(?:system|popen|exec)|exec|eval|subprocess|Runtime\.getRuntime)\b",
]

_CMDI_OUTPUT_SIGNATURES = [
    r"uid=\d+\(.*?\)\s+gid=\d+",
    r"(?:Linux|Darwin)\s+\S+\s+\d+\.\d+",
    r"total\s+\d+\s*\n(?:d|-)r[w-]",
    r"root:.*:0:0:",
    r"(?:bin|usr|etc|home|var)/",
]


def _check_cmdi(
    req_body: str,
    resp_body: str,
    query_params: str,
    url: str,
) -> list[Hint]:
    hints: list[Hint] = []
    combined_input = f"{url} {req_body} {query_params}"

    has_cmdi_in_request = False
    for pattern in _CMDI_PATTERNS:
        if re.search(pattern, combined_input, re.IGNORECASE):
            has_cmdi_in_request = True
            hints.append(Hint(
                category="Command Injection",
                indicator="OS command pattern in request input",
                evidence=f"Pattern: {pattern}",
                confidence=0.65,
                cwe_id="CWE-78",
                severity_suggestion="critical",
                owasp="A03:2021-Injection",
            ))
            break

    if has_cmdi_in_request:
        for pattern in _CMDI_OUTPUT_SIGNATURES:
            if re.search(pattern, resp_body):
                hints.append(Hint(
                    category="Command Injection",
                    indicator="OS command output signature in response",
                    evidence=f"Pattern: {pattern}",
                    confidence=0.85,
                    cwe_id="CWE-78",
                    severity_suggestion="critical",
                    owasp="A03:2021-Injection",
                ))
                break

    return hints


# ---------------------------------------------------------------------------
# XXE Detection (dmass xxe-detector)
# ---------------------------------------------------------------------------

_XXE_PAYLOAD_PATTERNS = [
    r"<!DOCTYPE[^>]*\[.*<!ENTITY",
    r"<!ENTITY\s+\w+\s+SYSTEM",
    r"<!ENTITY\s+%\s+\w+\s+SYSTEM",
    r"SYSTEM\s+[\"'](?:file|http|https|ftp|gopher|expect|php)://",
    r"<!ENTITY\s+\w+\s+PUBLIC",
]

_XXE_OUTPUT_PATTERNS = [
    r"root:.*:0:0:",
    r"\[boot loader\]",
    r"<!DOCTYPE",
    r"SYSTEM\s+\"",
]


def _check_xxe(
    req_body: str,
    resp_body: str,
    content_type: str,
) -> list[Hint]:
    hints: list[Hint] = []
    is_xml = "xml" in content_type.lower()

    for pattern in _XXE_PAYLOAD_PATTERNS:
        if re.search(pattern, req_body, re.IGNORECASE | re.DOTALL):
            hints.append(Hint(
                category="XXE",
                indicator="XML external entity declaration in request body",
                evidence=f"Pattern: {pattern}",
                confidence=0.75 if is_xml else 0.55,
                cwe_id="CWE-611",
                severity_suggestion="high",
                owasp="A05:2021-Security Misconfiguration",
            ))
            break

    for pattern in _XXE_OUTPUT_PATTERNS:
        if re.search(pattern, resp_body) and is_xml:
            hints.append(Hint(
                category="XXE",
                indicator="Possible XXE output (file content or entity expansion) in response",
                evidence=f"Pattern: {pattern}",
                confidence=0.70,
                cwe_id="CWE-611",
                severity_suggestion="high",
                owasp="A05:2021-Security Misconfiguration",
            ))
            break

    return hints


# ---------------------------------------------------------------------------
# SSRF Detection (dmass ssrf-detector + cloud-metadata-prober)
# ---------------------------------------------------------------------------

_SSRF_INDICATORS = [
    r"(?:127\.0\.0\.1|localhost|0\.0\.0\.0|::1|0x7f)",
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"169\.254\.170\.2",
    r"(?:file|gopher|dict|ldap|tftp)://",
    r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})",
    r"@(?:127\.0\.0\.1|localhost|169\.254)",
    r"(?:url|uri|path|file|page|src|href|redirect|next|return|goto|dest|target)\s*=\s*(?:https?://|//)",
]

_SSRF_RESPONSE_INDICATORS = [
    r"ami-id|instance-id|instance-type",
    r"access_token.*project-id",
    r"compute\.internal",
    r"iam/security-credentials",
    r"kube-system|kubernetes\.io",
]


def _check_ssrf(
    url: str,
    req_body: str,
    resp_body: str,
    query_params: str,
) -> list[Hint]:
    hints: list[Hint] = []
    combined_input = f"{url} {req_body} {query_params}"

    for pattern in _SSRF_INDICATORS:
        if re.search(pattern, combined_input, re.IGNORECASE):
            hints.append(Hint(
                category="SSRF",
                indicator="Internal/metadata URL or SSRF-prone parameter in request",
                evidence=f"Pattern: {pattern}",
                confidence=0.60,
                cwe_id="CWE-918",
                severity_suggestion="high",
                owasp="A10:2021-SSRF",
            ))
            break

    for pattern in _SSRF_RESPONSE_INDICATORS:
        if re.search(pattern, resp_body, re.IGNORECASE):
            hints.append(Hint(
                category="SSRF",
                indicator="Cloud metadata or internal service response detected",
                evidence=f"Pattern: {pattern}",
                confidence=0.85,
                cwe_id="CWE-918",
                severity_suggestion="critical",
                owasp="A10:2021-SSRF",
            ))
            break

    return hints


# ---------------------------------------------------------------------------
# Path Traversal (dmass path-traversal-detector + Nuclei patterns)
# ---------------------------------------------------------------------------

_PATH_TRAVERSAL_PATTERNS = [
    r"(?:\.\./|\.\.\\){2,}",
    r"(?:%2e%2e%2f|%2e%2e/|\.\.%2f){2,}",
    r"(?:%252e%252e%252f){2,}",
    r"(?:%c0%ae%c0%ae%c0%af){2,}",
    r"(?:etc/passwd|etc/shadow|etc/hosts|windows/system32|boot\.ini|win\.ini)",
    r"(?:/proc/self/|/dev/null|/dev/tcp)",
    r"\.\./\.\./\.\./\.\./\.\./",
]


def _check_path_traversal(
    url: str,
    req_body: str,
    resp_body: str,
    query_params: str,
) -> list[Hint]:
    hints: list[Hint] = []
    combined_input = f"{url} {req_body} {query_params}"

    for pattern in _PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, combined_input, re.IGNORECASE):
            hints.append(Hint(
                category="Path Traversal",
                indicator="Directory traversal sequence in request",
                evidence=f"Pattern: {pattern}",
                confidence=0.70,
                cwe_id="CWE-22",
                severity_suggestion="high",
                owasp="A01:2021-Broken Access Control",
            ))
            break

    if re.search(r"root:.*:0:0:", resp_body):
        hints.append(Hint(
            category="Path Traversal",
            indicator="/etc/passwd content in response",
            evidence="root:x:0:0 pattern detected",
            confidence=0.90,
            cwe_id="CWE-22",
            severity_suggestion="critical",
            owasp="A01:2021-Broken Access Control",
        ))

    return hints


# ---------------------------------------------------------------------------
# HTTP Request Smuggling (dmass smuggling-detector)
# ---------------------------------------------------------------------------

def _check_http_smuggling(
    req_headers: dict,
    resp_body: str,
    resp_headers: dict,
) -> list[Hint]:
    hints: list[Hint] = []

    has_cl = any(k.lower() == "content-length" for k in req_headers)
    has_te = any(k.lower() == "transfer-encoding" for k in req_headers)

    if has_cl and has_te:
        hints.append(Hint(
            category="HTTP Request Smuggling",
            indicator="Both Content-Length and Transfer-Encoding present",
            evidence="CL.TE or TE.CL smuggling vector possible",
            confidence=0.60,
            cwe_id="CWE-444",
            severity_suggestion="high",
            owasp="A05:2021-Security Misconfiguration",
        ))

    te_values = [v for k, v in req_headers.items() if k.lower() == "transfer-encoding"]
    for v in te_values:
        if v.lower() not in ("chunked", "identity", "gzip", "compress", "deflate"):
            hints.append(Hint(
                category="HTTP Request Smuggling",
                indicator="Obfuscated Transfer-Encoding header value",
                evidence=f"TE value: {v}",
                confidence=0.55,
                cwe_id="CWE-444",
                severity_suggestion="high",
                owasp="A05:2021-Security Misconfiguration",
            ))

    return hints


# ---------------------------------------------------------------------------
# JWT Vulnerabilities (dmass jwt-auditor)
# ---------------------------------------------------------------------------

_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _check_jwt(
    req_headers: dict,
    resp_headers: dict,
    resp_body: str,
    url: str,
) -> list[Hint]:
    hints: list[Hint] = []
    combined = f"{json.dumps(req_headers)} {json.dumps(resp_headers)} {resp_body}"

    jwt_tokens = _JWT_PATTERN.findall(combined)
    for token in jwt_tokens:
        import base64
        try:
            header_b64 = token.split(".")[0]
            padding = 4 - len(header_b64) % 4
            header_json = base64.urlsafe_b64decode(header_b64 + "=" * padding)
            header = json.loads(header_json)
        except Exception:
            continue

        alg = header.get("alg", "")
        if alg.lower() == "none":
            hints.append(Hint(
                category="JWT - Algorithm None",
                indicator="JWT with alg:none detected (signature bypass)",
                evidence=f"Token header: {header}",
                confidence=0.90,
                cwe_id="CWE-327",
                severity_suggestion="critical",
                owasp="A02:2021-Cryptographic Failures",
            ))
        elif alg.upper() == "HS256" and header.get("typ") == "JWT":
            hints.append(Hint(
                category="JWT - Weak Algorithm",
                indicator="JWT uses HS256 (susceptible to key confusion if RS256 expected)",
                evidence=f"Token header: {header}",
                confidence=0.40,
                cwe_id="CWE-327",
                severity_suggestion="medium",
                owasp="A02:2021-Cryptographic Failures",
            ))

        sig = token.split(".")[-1]
        if not sig or sig == "":
            hints.append(Hint(
                category="JWT - Empty Signature",
                indicator="JWT token has empty signature",
                evidence=f"Token: {token[:80]}...",
                confidence=0.85,
                cwe_id="CWE-345",
                severity_suggestion="critical",
                owasp="A02:2021-Cryptographic Failures",
            ))

    return hints


# ---------------------------------------------------------------------------
# IDOR / Broken Access Control (dmass idor-detector heuristics)
# ---------------------------------------------------------------------------

_IDOR_URL_PATTERNS = [
    r"/(?:users?|accounts?|profiles?|orders?|invoices?|documents?|files?|records?|messages?)/(\d+)",
    r"[?&](?:id|user_id|account_id|order_id|doc_id|file_id|record_id)=(\d+)",
    r"/(?:api/)?v\d+/\w+/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
]


def _check_idor(
    url: str,
    method: str,
    status_code: int | None,
) -> list[Hint]:
    hints: list[Hint] = []

    for pattern in _IDOR_URL_PATTERNS:
        match = re.search(pattern, url, re.IGNORECASE)
        if match:
            hints.append(Hint(
                category="IDOR",
                indicator="Sequential/predictable resource ID in URL",
                evidence=f"URL: {url}, ID: {match.group(1)}",
                confidence=0.35,
                cwe_id="CWE-639",
                severity_suggestion="medium",
                owasp="A01:2021-Broken Access Control",
            ))
            break

    return hints


# ---------------------------------------------------------------------------
# Mass Assignment (dmass mass-assignment-detector)
# ---------------------------------------------------------------------------

_PRIVILEGED_FIELDS = {
    "role", "isAdmin", "is_admin", "admin", "user_level", "userLevel",
    "permission", "permissions", "credits", "balance",
    "verified", "email_verified", "emailVerified", "active",
    "account_type", "accountType", "subscription_level",
    "groups", "scopes", "is_superuser", "is_staff",
    "privilege", "access_level", "accessLevel", "tier",
}

_PRIVILEGED_FIELDS_LOWER = {f.lower() for f in _PRIVILEGED_FIELDS}


def _check_mass_assignment(
    method: str,
    req_body: str,
    content_type: str,
) -> list[Hint]:
    hints: list[Hint] = []

    if method not in ("POST", "PUT", "PATCH"):
        return hints

    body_lower = req_body.lower()
    found_fields = []

    try:
        if "json" in content_type.lower():
            data = json.loads(req_body)
            if isinstance(data, dict):
                for key in data:
                    if key.lower() in _PRIVILEGED_FIELDS_LOWER:
                        found_fields.append(key)
    except (json.JSONDecodeError, TypeError):
        for field_name in _PRIVILEGED_FIELDS:
            if field_name.lower() in body_lower:
                found_fields.append(field_name)

    if found_fields:
        hints.append(Hint(
            category="Mass Assignment",
            indicator=f"Privileged fields in request body: {', '.join(found_fields)}",
            evidence=f"Fields: {found_fields}",
            confidence=0.50 if len(found_fields) >= 2 else 0.35,
            cwe_id="CWE-915",
            severity_suggestion="high" if len(found_fields) >= 2 else "medium",
            owasp="A01:2021-Broken Access Control",
        ))

    return hints


# ---------------------------------------------------------------------------
# Security Headers Analysis (OWASP ZAP passive rules)
# ---------------------------------------------------------------------------

_REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS missing — vulnerable to protocol downgrade",
    "Content-Security-Policy": "CSP missing — increased XSS risk",
    "X-Content-Type-Options": "X-Content-Type-Options missing — MIME sniffing risk",
    "X-Frame-Options": "X-Frame-Options missing — clickjacking risk",
    "Referrer-Policy": "Referrer-Policy missing — potential info leakage",
    "Permissions-Policy": "Permissions-Policy missing — browser feature abuse risk",
}


def _check_security_headers(resp_headers: dict) -> list[str]:
    missing = []
    normalized = {k.lower(): v for k, v in resp_headers.items()}

    for header, desc in _REQUIRED_SECURITY_HEADERS.items():
        if header.lower() not in normalized:
            missing.append(f"{header}: {desc}")

    return missing


# ---------------------------------------------------------------------------
# CORS Misconfiguration (Burp Suite + ZAP patterns)
# ---------------------------------------------------------------------------

def _check_cors(
    req_headers: dict,
    resp_headers: dict,
) -> list[Hint]:
    hints: list[Hint] = []
    acao = resp_headers.get("Access-Control-Allow-Origin", resp_headers.get("access-control-allow-origin", ""))

    if acao == "*":
        acac = resp_headers.get(
            "Access-Control-Allow-Credentials",
            resp_headers.get("access-control-allow-credentials", ""),
        )
        if acac.lower() == "true":
            hints.append(Hint(
                category="CORS Misconfiguration",
                indicator="Wildcard origin (*) with Allow-Credentials: true",
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                confidence=0.90,
                cwe_id="CWE-942",
                severity_suggestion="high",
                owasp="A05:2021-Security Misconfiguration",
            ))
        else:
            hints.append(Hint(
                category="CORS Misconfiguration",
                indicator="Wildcard origin (*) — may be intentional for public APIs",
                evidence=f"ACAO: {acao}",
                confidence=0.35,
                cwe_id="CWE-942",
                severity_suggestion="low",
                owasp="A05:2021-Security Misconfiguration",
            ))

    origin = req_headers.get("Origin", req_headers.get("origin", ""))
    if origin and acao == origin:
        hints.append(Hint(
            category="CORS Misconfiguration",
            indicator="Origin reflected directly in ACAO (possible open redirect via CORS)",
            evidence=f"Origin: {origin} → ACAO: {acao}",
            confidence=0.65,
            cwe_id="CWE-942",
            severity_suggestion="medium",
            owasp="A05:2021-Security Misconfiguration",
        ))

    return hints


# ---------------------------------------------------------------------------
# Sensitive Data Exposure (dmass secrets-scanner + Nuclei)
# ---------------------------------------------------------------------------

_SECRETS_PATTERNS: list[tuple[str, str, str]] = [
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID", "CWE-798"),
    (r"(?:aws_secret_access_key|AWS_SECRET)\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}", "AWS Secret Key", "CWE-798"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", "CWE-798"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", "CWE-798"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key", "CWE-798"),
    (r"sk_live_[A-Za-z0-9]{24,}", "Stripe Live Secret Key", "CWE-798"),
    (r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}", "OpenAI API Key", "CWE-798"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,48}", "Slack Token", "CWE-798"),
    (r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----", "Private Key", "CWE-321"),
    (r"(?:mongodb|mysql|postgres|redis|amqp)://[^\s'\"]+:[^\s'\"]+@", "Database Connection String", "CWE-798"),
    (r"[a-f0-9]{32}-us\d{1,2}", "Mailchimp API Key", "CWE-798"),
    (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid API Key", "CWE-798"),
    (r"(?:password|passwd|pwd|secret|token|api_key|apikey)\s*[:=]\s*['\"][^'\"]{8,}['\"]", "Hardcoded Secret", "CWE-798"),
]


def _check_sensitive_data(resp_body: str, resp_headers: dict) -> list[Hint]:
    hints: list[Hint] = []

    for pattern, name, cwe in _SECRETS_PATTERNS:
        match = re.search(pattern, resp_body)
        if match:
            hints.append(Hint(
                category="Sensitive Data Exposure",
                indicator=f"{name} found in response body",
                evidence=f"Matched: {match.group(0)[:40]}...",
                confidence=0.80,
                cwe_id=cwe,
                severity_suggestion="critical" if "Private Key" in name or "Secret" in name else "high",
                owasp="A02:2021-Cryptographic Failures",
            ))

    if resp_headers.get("Server") or resp_headers.get("server"):
        server = resp_headers.get("Server", resp_headers.get("server", ""))
        if re.search(r"(?:Apache|nginx|IIS|Express|Kestrel)/[\d.]+", server, re.IGNORECASE):
            hints.append(Hint(
                category="Information Disclosure",
                indicator=f"Server version exposed: {server}",
                evidence=f"Server header: {server}",
                confidence=0.70,
                cwe_id="CWE-200",
                severity_suggestion="low",
                owasp="A05:2021-Security Misconfiguration",
            ))

    x_powered = resp_headers.get("X-Powered-By", resp_headers.get("x-powered-by", ""))
    if x_powered:
        hints.append(Hint(
            category="Information Disclosure",
            indicator=f"X-Powered-By header exposes technology: {x_powered}",
            evidence=f"X-Powered-By: {x_powered}",
            confidence=0.65,
            cwe_id="CWE-200",
            severity_suggestion="low",
            owasp="A05:2021-Security Misconfiguration",
        ))

    return hints


# ---------------------------------------------------------------------------
# Technology Fingerprinting (dmass tech-fingerprinter)
# ---------------------------------------------------------------------------

_TECH_SIGNATURES: list[tuple[str, str]] = [
    (r"(?:react|__NEXT_DATA__|next\.js)", "React/Next.js"),
    (r"(?:vue|__vue__|nuxt)", "Vue.js/Nuxt"),
    (r"(?:angular|ng-version)", "Angular"),
    (r"(?:express|connect\.sid)", "Express.js"),
    (r"(?:laravel_session|XSRF-TOKEN.*laravel)", "Laravel"),
    (r"(?:django|csrfmiddlewaretoken)", "Django"),
    (r"(?:flask|Werkzeug)", "Flask"),
    (r"(?:ASP\.NET|__VIEWSTATE|__EVENTVALIDATION)", "ASP.NET"),
    (r"(?:spring|JSESSIONID)", "Spring/Java"),
    (r"(?:wordpress|wp-content|wp-json)", "WordPress"),
    (r"(?:php|PHPSESSID)", "PHP"),
    (r"(?:ruby|rack\.session)", "Ruby/Rails"),
    (r"(?:graphql|__schema|introspection)", "GraphQL"),
]

_WAF_SIGNATURES: list[tuple[str, str]] = [
    (r"cf-ray", "Cloudflare"),
    (r"x-amzn-requestid|awselb", "AWS WAF/ALB"),
    (r"x-akamai-transformed", "Akamai"),
    (r"x-iinfo|_incap_ses", "Imperva/Incapsula"),
    (r"Server:\s*BIG-IP", "F5 BIG-IP"),
    (r"x-azure-ref", "Azure Front Door"),
    (r"x-sucuri", "Sucuri"),
    (r"x-cdn.*fastly", "Fastly"),
]


def _fingerprint(resp_body: str, resp_headers: dict) -> tuple[list[str], str]:
    techs = []
    combined = f"{resp_body} {json.dumps(resp_headers)}"

    for pattern, name in _TECH_SIGNATURES:
        if re.search(pattern, combined, re.IGNORECASE):
            techs.append(name)

    waf = ""
    header_str = json.dumps(resp_headers).lower()
    for pattern, name in _WAF_SIGNATURES:
        if re.search(pattern, header_str, re.IGNORECASE):
            waf = name
            break

    return techs, waf


# ---------------------------------------------------------------------------
# GraphQL Introspection / Injection (Nuclei + Burp)
# ---------------------------------------------------------------------------

def _check_graphql(
    url: str,
    req_body: str,
    resp_body: str,
) -> list[Hint]:
    hints: list[Hint] = []

    if "graphql" not in url.lower() and "graphql" not in req_body.lower():
        return hints

    if "__schema" in resp_body or "__type" in resp_body or "introspectionQuery" in req_body.lower():
        hints.append(Hint(
            category="GraphQL Introspection Enabled",
            indicator="GraphQL introspection is enabled (full schema exposed)",
            evidence="__schema or __type found in response",
            confidence=0.85,
            cwe_id="CWE-200",
            severity_suggestion="medium",
            owasp="A05:2021-Security Misconfiguration",
        ))

    if re.search(r'(?:query|mutation)\s*\{.*\{.*\{.*\{', req_body, re.DOTALL):
        hints.append(Hint(
            category="GraphQL Depth Attack",
            indicator="Deeply nested GraphQL query (possible DoS)",
            evidence="4+ levels of nesting detected",
            confidence=0.50,
            cwe_id="CWE-400",
            severity_suggestion="medium",
            owasp="A05:2021-Security Misconfiguration",
        ))

    return hints


# ---------------------------------------------------------------------------
# Open Redirect (OWASP ZAP)
# ---------------------------------------------------------------------------

_REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "return", "returnTo",
    "return_to", "next", "url", "goto", "dest", "destination",
    "continue", "target", "rurl", "callback",
}


def _check_open_redirect(
    url: str,
    query_params: str,
    status_code: int | None,
    resp_headers: dict,
) -> list[Hint]:
    hints: list[Hint] = []
    parsed = parse_qs(query_params) if query_params else {}
    full_parsed = parse_qs(urlparse(url).query)
    parsed.update(full_parsed)

    for param, values in parsed.items():
        if param.lower() in _REDIRECT_PARAMS:
            for val in values:
                if re.match(r"^(?:https?://|//)[^/]", val):
                    confidence = 0.70 if status_code and 300 <= status_code < 400 else 0.45
                    hints.append(Hint(
                        category="Open Redirect",
                        indicator=f"External URL in redirect parameter '{param}'",
                        evidence=f"{param}={val}",
                        confidence=confidence,
                        cwe_id="CWE-601",
                        severity_suggestion="medium",
                        owasp="A01:2021-Broken Access Control",
                    ))
                    break

    location = resp_headers.get("Location", resp_headers.get("location", ""))
    if location and status_code and 300 <= status_code < 400:
        for param, values in parsed.items():
            for val in values:
                if val in location:
                    hints.append(Hint(
                        category="Open Redirect",
                        indicator="User-controlled value reflected in Location header",
                        evidence=f"Parameter '{param}' value in Location: {location[:200]}",
                        confidence=0.75,
                        cwe_id="CWE-601",
                        severity_suggestion="medium",
                        owasp="A01:2021-Broken Access Control",
                    ))

    return hints


# ---------------------------------------------------------------------------
# Insecure Deserialization (Burp + OWASP)
# ---------------------------------------------------------------------------

_DESERIALIZATION_PATTERNS = [
    (r"rO0AB", "Java serialized object (Base64)"),
    (r"aced0005", "Java serialized object (hex)"),
    (r"O:\d+:\"[^\"]+\":\d+:\{", "PHP serialized object"),
    (r"(?:pickle|cpickle|marshal)\.loads", "Python pickle deserialization"),
    (r"yaml\.(?:load|unsafe_load)", "Python YAML unsafe load"),
    (r"ObjectInputStream", "Java ObjectInputStream"),
    (r"__reduce__|__setstate__", "Python pickle magic methods"),
]


def _check_deserialization(
    req_body: str,
    resp_body: str,
) -> list[Hint]:
    hints: list[Hint] = []
    combined = f"{req_body} {resp_body}"

    for pattern, name in _DESERIALIZATION_PATTERNS:
        if re.search(pattern, combined, re.IGNORECASE):
            hints.append(Hint(
                category="Insecure Deserialization",
                indicator=f"Deserialization signature: {name}",
                evidence=f"Pattern: {pattern}",
                confidence=0.55,
                cwe_id="CWE-502",
                severity_suggestion="high",
                owasp="A08:2021-Software and Data Integrity Failures",
            ))
            break

    return hints


# ---------------------------------------------------------------------------
# Session / Cookie Analysis (dmass session-auditor)
# ---------------------------------------------------------------------------

def _check_cookies(resp_headers: dict) -> list[Hint]:
    hints: list[Hint] = []
    set_cookies = []
    for k, v in resp_headers.items():
        if k.lower() == "set-cookie":
            set_cookies.append(v)

    for cookie in set_cookies:
        cookie_lower = cookie.lower()
        if "session" in cookie_lower or "token" in cookie_lower or "auth" in cookie_lower:
            if "httponly" not in cookie_lower:
                hints.append(Hint(
                    category="Insecure Cookie",
                    indicator="Session/auth cookie missing HttpOnly flag",
                    evidence=f"Cookie: {cookie[:100]}",
                    confidence=0.75,
                    cwe_id="CWE-1004",
                    severity_suggestion="medium",
                    owasp="A05:2021-Security Misconfiguration",
                ))
            if "secure" not in cookie_lower:
                hints.append(Hint(
                    category="Insecure Cookie",
                    indicator="Session/auth cookie missing Secure flag",
                    evidence=f"Cookie: {cookie[:100]}",
                    confidence=0.70,
                    cwe_id="CWE-614",
                    severity_suggestion="medium",
                    owasp="A05:2021-Security Misconfiguration",
                ))
            if "samesite" not in cookie_lower:
                hints.append(Hint(
                    category="Insecure Cookie",
                    indicator="Session/auth cookie missing SameSite attribute",
                    evidence=f"Cookie: {cookie[:100]}",
                    confidence=0.55,
                    cwe_id="CWE-1275",
                    severity_suggestion="low",
                    owasp="A05:2021-Security Misconfiguration",
                ))

    return hints


# ---------------------------------------------------------------------------
# CSRF Detection (Burp passive)
# ---------------------------------------------------------------------------

def _check_csrf(
    method: str,
    req_headers: dict,
    req_body: str,
    content_type: str,
) -> list[Hint]:
    hints: list[Hint] = []

    if method not in ("POST", "PUT", "PATCH", "DELETE"):
        return hints

    csrf_header_names = {"x-csrf-token", "x-xsrf-token", "x-requested-with", "csrf-token"}
    has_csrf_header = any(k.lower() in csrf_header_names for k in req_headers)

    csrf_body_names = {"csrf", "csrftoken", "_token", "authenticity_token", "__requestverificationtoken", "csrfmiddlewaretoken"}
    has_csrf_body = any(name in req_body.lower() for name in csrf_body_names)

    if not has_csrf_header and not has_csrf_body:
        if "json" not in content_type.lower():
            hints.append(Hint(
                category="CSRF",
                indicator="State-changing request without CSRF token",
                evidence=f"Method: {method}, no CSRF header or body parameter detected",
                confidence=0.50,
                cwe_id="CWE-352",
                severity_suggestion="medium",
                owasp="A01:2021-Broken Access Control",
            ))

    return hints


# ---------------------------------------------------------------------------
# Rate Limiting / Brute Force Detection
# ---------------------------------------------------------------------------

def _check_auth_weakness(
    url: str,
    method: str,
    req_body: str,
    resp_headers: dict,
    status_code: int | None,
) -> list[Hint]:
    hints: list[Hint] = []

    auth_paths = {"login", "signin", "sign-in", "auth", "authenticate", "token", "oauth", "register", "signup", "password", "reset"}
    path = urlparse(url).path.lower()
    is_auth_endpoint = any(p in path for p in auth_paths)

    if is_auth_endpoint and method == "POST":
        rate_limit_headers = {"x-ratelimit-limit", "x-rate-limit-limit", "retry-after", "ratelimit-limit"}
        has_rate_limit = any(k.lower() in rate_limit_headers for k in resp_headers)
        if not has_rate_limit:
            hints.append(Hint(
                category="Missing Rate Limiting",
                indicator="Authentication endpoint without rate limiting headers",
                evidence=f"URL: {url}",
                confidence=0.40,
                cwe_id="CWE-307",
                severity_suggestion="medium",
                owasp="A07:2021-Identification and Authentication Failures",
            ))

    return hints


# ---------------------------------------------------------------------------
# Helper: extract all parameter values
# ---------------------------------------------------------------------------

def _extract_all_params(url: str, req_body: str, query_params: str) -> list[str]:
    values: list[str] = []

    parsed_q = parse_qs(query_params) if query_params else {}
    for vs in parsed_q.values():
        values.extend(vs)

    url_q = parse_qs(urlparse(url).query)
    for vs in url_q.values():
        values.extend(vs)

    try:
        body_data = json.loads(req_body)
        if isinstance(body_data, dict):
            for v in body_data.values():
                if isinstance(v, str):
                    values.append(v)
    except (json.JSONDecodeError, TypeError):
        for pair in req_body.split("&"):
            if "=" in pair:
                values.append(unquote_plus(pair.split("=", 1)[1]))

    return values


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_pre_analysis(
    method: str,
    url: str,
    content_type: str,
    request_headers: str,
    request_body: str,
    status_code: int | None,
    response_headers: str,
    response_body: str,
    query_params: str = "",
) -> PreAnalysisResult:
    try:
        req_hdr: dict = json.loads(request_headers) if request_headers else {}
    except (json.JSONDecodeError, TypeError):
        req_hdr = {}
    try:
        resp_hdr: dict = json.loads(response_headers) if response_headers else {}
    except (json.JSONDecodeError, TypeError):
        resp_hdr = {}

    result = PreAnalysisResult()

    result.detected_tech, result.waf_detected = _fingerprint(response_body, resp_hdr)
    result.security_headers_missing = _check_security_headers(resp_hdr)

    checkers = [
        lambda: _check_sqli(url, request_body, response_body, query_params),
        lambda: _check_nosql(request_body, response_body, query_params, content_type),
        lambda: _check_xss(url, request_body, response_body, query_params, req_hdr),
        lambda: _check_ssti(request_body, response_body, query_params),
        lambda: _check_cmdi(request_body, response_body, query_params, url),
        lambda: _check_xxe(request_body, response_body, content_type),
        lambda: _check_ssrf(url, request_body, response_body, query_params),
        lambda: _check_path_traversal(url, request_body, response_body, query_params),
        lambda: _check_http_smuggling(req_hdr, response_body, resp_hdr),
        lambda: _check_jwt(req_hdr, resp_hdr, response_body, url),
        lambda: _check_idor(url, method, status_code),
        lambda: _check_mass_assignment(method, request_body, content_type),
        lambda: _check_cors(req_hdr, resp_hdr),
        lambda: _check_sensitive_data(response_body, resp_hdr),
        lambda: _check_graphql(url, request_body, response_body),
        lambda: _check_open_redirect(url, query_params, status_code, resp_hdr),
        lambda: _check_deserialization(request_body, response_body),
        lambda: _check_cookies(resp_hdr),
        lambda: _check_csrf(method, req_hdr, request_body, content_type),
        lambda: _check_auth_weakness(url, method, request_body, resp_hdr, status_code),
    ]

    for checker in checkers:
        try:
            result.hints.extend(checker())
        except Exception:
            logger.debug("Pre-analysis checker failed", exc_info=True)

    logger.info(
        "Pre-analysis: %d hints, %d techs, waf=%s, missing_headers=%d",
        len(result.hints),
        len(result.detected_tech),
        result.waf_detected or "none",
        len(result.security_headers_missing),
    )

    return result
