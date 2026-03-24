#!/usr/bin/env python3
"""
Security Header Analysis Version 2026
by camp4

Features:
- Analyse one URL or many URLs from a file
- Custom headers support
- Web / API mode
- HEAD with GET fallback
- Redirect chain analysis
- Deprecated header review
- Misconfiguration analysis
- JSON export
- HTML report export
- Friendly coloured output

Install:
    pip install requests

Examples:
    python3 security_header_analysis_2026.py -u example.com -t web
    python3 security_header_analysis_2026.py -u https://api.example.com/v1/me -t api -H "Authorization: Bearer test" -k
    python3 security_header_analysis_2026.py -f targets.txt -t web --json-out results.json --html-out report.html
"""

import argparse
import html
import json
import re
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================
# ANSI COLOURS
# ============================================================
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def colour(text, col):
    return f"{col}{text}{C.RESET}"


def good(text):
    return colour(text, C.GREEN)


def warn(text):
    return colour(text, C.YELLOW)


def bad(text):
    return colour(text, C.RED)


def info(text):
    return colour(text, C.CYAN)


# ============================================================
# BANNER
# ============================================================
def print_banner():
    banner = f"""
{C.BOLD}{C.BLUE}
===============================================================
   SECURITY HEADER ANALYSIS VERSION 2026
   by camp4
===============================================================
{C.RESET}
"""
    print(banner)


# ============================================================
# HEADER BASELINES
# ============================================================
WEB_HEADERS = [
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "X-Permitted-Cross-Domain-Policies",
    "Referrer-Policy",
    "Clear-Site-Data",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cache-Control",
    "X-DNS-Prefetch-Control",
]

API_HEADERS = [
    "Cache-Control",
    "Content-Security-Policy",
    "Content-Type",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
]

DEPRECATED_HEADERS = [
    "Feature-Policy",
    "Expect-CT",
    "Public-Key-Pins",
    "X-XSS-Protection",
    "Pragma",
]


# ============================================================
# HELPERS
# ============================================================
def normalise_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("Empty URL provided.")

    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw

    parsed = urlparse(raw)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {raw}")

    return raw


def headers_casefold_dict(headers):
    return {k.lower(): v for k, v in headers.items()}


def get_header(hdict, name):
    return hdict.get(name.lower())


def parse_header_args(header_list):
    headers = {}
    for item in header_list or []:
        if ":" not in item:
            raise ValueError(f"Invalid header format: {item} (expected 'Header: value')")
        name, value = item.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            raise ValueError(f"Invalid header name in: {item}")
        headers[name] = value
    return headers


def load_targets_from_file(path):
    targets = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(line)
    return targets


# ============================================================
# REQUEST LOGIC
# ============================================================
def perform_request(url, headers, verify_tls=True, timeout=20, force_method="auto"):
    """
    auto:
      1. try HEAD
      2. if HEAD fails, suspicious, or empty-ish, fallback to GET
    """
    session = requests.Session()
    method_used = None
    response = None
    notes = []

    if force_method.upper() == "GET":
        method_used = "GET"
        response = session.get(url, headers=headers, verify=verify_tls, timeout=timeout, allow_redirects=True)
        return response, method_used, notes

    if force_method.upper() == "HEAD":
        method_used = "HEAD"
        response = session.head(url, headers=headers, verify=verify_tls, timeout=timeout, allow_redirects=True)
        return response, method_used, notes

    try:
        method_used = "HEAD"
        response = session.head(url, headers=headers, verify=verify_tls, timeout=timeout, allow_redirects=True)

        # Some servers don't behave well with HEAD
        suspicious_head = (
            response.status_code >= 400 or
            len(response.headers) == 0 or
            response.status_code in [405, 501]
        )

        if suspicious_head:
            notes.append("HEAD response was incomplete or unsupported; GET fallback used.")
            method_used = "GET"
            response = session.get(url, headers=headers, verify=verify_tls, timeout=timeout, allow_redirects=True)

    except requests.RequestException:
        notes.append("HEAD request failed; GET fallback used.")
        method_used = "GET"
        response = session.get(url, headers=headers, verify=verify_tls, timeout=timeout, allow_redirects=True)

    return response, method_used, notes


# ============================================================
# ANALYSIS
# ============================================================
def analyse_csp(csp_value):
    findings = []
    if not csp_value:
        return findings

    v = csp_value.lower()

    if "'unsafe-inline'" in v:
        findings.append(("warning", "CSP contains 'unsafe-inline', which weakens protection against script/style injection."))
    if "'unsafe-eval'" in v:
        findings.append(("warning", "CSP contains 'unsafe-eval', which weakens protection against unsafe script execution."))
    if re.search(r"(^|[\s;])default-src\s+\*", v):
        findings.append(("warning", "CSP uses 'default-src *', which is overly permissive."))
    if re.search(r"(^|[\s;])script-src[^;]*\*", v):
        findings.append(("warning", "CSP uses wildcard sources in 'script-src', which may be overly permissive."))
    if re.search(r"(^|[\s;])connect-src[^;]*\*", v):
        findings.append(("info", "CSP uses wildcard sources in 'connect-src'; verify that broad network access is required."))
    if "http:" in v:
        findings.append(("warning", "CSP allows 'http:' sources, which may permit insecure content loading."))
    if "data:" in v:
        findings.append(("info", "CSP allows 'data:' sources; review whether this is necessary."))
    if "object-src" not in v:
        findings.append(("info", "CSP does not define 'object-src'; consider 'object-src none'."))
    if "base-uri" not in v:
        findings.append(("info", "CSP does not define 'base-uri'; consider restricting it."))
    if "frame-ancestors" not in v:
        findings.append(("info", "CSP is present but does not define 'frame-ancestors'."))
    if "report-uri" not in v and "report-to" not in v:
        findings.append(("info", "CSP does not define reporting directives ('report-uri' or 'report-to')."))

    return findings


def analyse_hsts(hsts_value):
    findings = []
    if not hsts_value:
        return findings

    v = hsts_value.lower()
    max_age_match = re.search(r"max-age=(\d+)", v)

    if not max_age_match:
        findings.append(("warning", "HSTS is present but does not clearly define max-age."))
    else:
        max_age = int(max_age_match.group(1))
        if max_age < 31536000:
            findings.append(("warning", "HSTS max-age is lower than 31536000 seconds (1 year)."))

    if "includesubdomains" not in v:
        findings.append(("info", "HSTS does not include 'includeSubDomains'."))
    if "preload" not in v:
        findings.append(("info", "HSTS does not include 'preload'."))

    return findings


def analyse_x_frame_options(value):
    findings = []
    if not value:
        return findings
    low = value.lower()
    if low not in {"deny", "sameorigin"} and not low.startswith("allow-from"):
        findings.append(("warning", f"X-Frame-Options has an unusual or invalid value: {value}"))
    return findings


def analyse_x_content_type_options(value):
    findings = []
    if value and value.lower() != "nosniff":
        findings.append(("warning", "X-Content-Type-Options should normally be set to 'nosniff'."))
    return findings


def analyse_referrer_policy(value):
    findings = []
    if not value:
        return findings
    low = value.lower()
    weak_values = {"unsafe-url", "no-referrer-when-downgrade"}
    if low in weak_values:
        findings.append(("warning", f"Referrer-Policy '{value}' may disclose more referrer information than necessary."))
    return findings


def analyse_cache_control(value, target_type):
    findings = []
    if not value:
        return findings
    low = value.lower()

    if target_type == "web":
        if "no-store" not in low and "private" not in low:
            findings.append(("info", "Cache-Control does not include 'no-store' or 'private'; review caching of sensitive web content."))
    else:
        if "no-store" not in low and "no-cache" not in low and "private" not in low:
            findings.append(("info", "API caching directives may be too permissive for sensitive responses."))

    return findings


def analyse_content_type(value, target_type):
    findings = []
    if not value:
        return findings

    low = value.lower()
    if target_type == "api":
        allowed = ["application/json", "application/xml", "text/plain"]
        if not any(x in low for x in allowed):
            findings.append(("info", f"API Content-Type is '{value}'. Verify that this is expected."))
    return findings


def analyse_cross_origin_headers(headers_cf):
    findings = []

    coep = get_header(headers_cf, "Cross-Origin-Embedder-Policy")
    coop = get_header(headers_cf, "Cross-Origin-Opener-Policy")
    corp = get_header(headers_cf, "Cross-Origin-Resource-Policy")

    if coep and coep.lower() not in {"require-corp", "credentialless"}:
        findings.append(("warning", f"Cross-Origin-Embedder-Policy has an unusual value: {coep}"))

    if coop and coop.lower() not in {"same-origin", "same-origin-allow-popups", "unsafe-none"}:
        findings.append(("warning", f"Cross-Origin-Opener-Policy has an unusual value: {coop}"))

    if corp and corp.lower() not in {"same-site", "same-origin", "cross-origin"}:
        findings.append(("warning", f"Cross-Origin-Resource-Policy has an unusual value: {corp}"))

    return findings


def analyse_x_dns_prefetch(value):
    findings = []
    if value and value.lower() not in {"on", "off"}:
        findings.append(("warning", f"X-DNS-Prefetch-Control has an unusual value: {value}"))
    return findings


def analyse_x_permitted_cross_domain_policies(value):
    findings = []
    if value and value.lower() not in {"none", "master-only", "by-content-type", "all"}:
        findings.append(("warning", f"X-Permitted-Cross-Domain-Policies has an unusual value: {value}"))
    return findings


def analyse_clear_site_data(value):
    findings = []
    if value:
        expected_tokens = ['"cache"', '"cookies"', '"storage"', '"executioncontexts"', "*"]
        if not any(token in value.lower() for token in expected_tokens):
            findings.append(("info", "Clear-Site-Data is present but uses an unusual value."))
    return findings


def header_status(name, value, target_type):
    if value is None:
        return "missing"

    v = value.strip()
    if not v:
        return "weak"

    low = v.lower()

    if name == "X-Content-Type-Options":
        return "good" if low == "nosniff" else "weak"

    if name == "X-Frame-Options":
        return "good" if low in {"deny", "sameorigin"} else "weak"

    if name == "Strict-Transport-Security":
        return "good" if "max-age=" in low else "weak"

    if name == "Content-Security-Policy":
        if "'unsafe-inline'" in low or "'unsafe-eval'" in low:
            return "weak"
        if re.search(r"(^|[\s;])default-src\s+\*", low):
            return "weak"
        return "good"

    if name == "Referrer-Policy":
        if low in {"unsafe-url", "no-referrer-when-downgrade"}:
            return "weak"
        return "good"

    if name == "Cache-Control":
        if target_type == "api":
            return "good" if ("no-store" in low or "no-cache" in low or "private" in low) else "weak"
        return "good" if ("no-store" in low or "private" in low) else "weak"

    return "good"


def analyse_redirect_chain(response):
    chain = []
    for r in response.history:
        chain.append({
            "url": r.url,
            "status_code": r.status_code,
            "location": r.headers.get("Location")
        })
    chain.append({
        "url": response.url,
        "status_code": response.status_code,
        "location": None
    })
    return chain


def compute_score(good_count, weak_count, missing_count):
    total = good_count + weak_count + missing_count
    if total == 0:
        return 0.0
    score = ((good_count * 1.0) + (weak_count * 0.5)) / total * 100
    return round(score, 1)


def analyse_response(target_url, response, target_type, method_used, notes):
    expected_headers = WEB_HEADERS if target_type == "web" else API_HEADERS
    headers_cf = headers_casefold_dict(response.headers)

    implemented = []
    deprecated_found = []
    findings = []

    good_count = 0
    weak_count = 0
    missing_count = 0

    for header in expected_headers:
        value = get_header(headers_cf, header)
        status = header_status(header, value, target_type)

        if status == "good":
            good_count += 1
        elif status == "weak":
            weak_count += 1
        else:
            missing_count += 1

        implemented.append({
            "header": header,
            "value": value,
            "status": status
        })

    for header in DEPRECATED_HEADERS:
        value = get_header(headers_cf, header)
        if value is not None:
            deprecated_found.append({
                "header": header,
                "value": value
            })

    findings.extend([{"level": lvl, "message": msg} for lvl, msg in analyse_csp(get_header(headers_cf, "Content-Security-Policy"))])
    findings.extend([{"level": lvl, "message": msg} for lvl, msg in analyse_hsts(get_header(headers_cf, "Strict-Transport-Security"))])
    findings.extend([{"level": lvl, "message": msg} for lvl, msg in analyse_x_frame_options(get_header(headers_cf, "X-Frame-Options"))])
    findings.extend([{"level": lvl, "message": msg} for lvl, msg in analyse_x_content_type_options(get_header(headers_cf, "X-Content-Type-Options"))])
    findings.extend([{"level": lvl, "message": msg} for lvl, msg in analyse_referrer_policy(get_header(headers_cf, "Referrer-Policy"))])
    findings.extend([{"level": lvl, "message": msg} for lvl, msg in analyse_cache_control(get_header(headers_cf, "Cache-Control"), target_type)])
    findings.extend([{"level": lvl, "message": msg} for lvl, msg in analyse_content_type(get_header(headers_cf, "Content-Type"), target_type)])
    findings.extend([{"level": lvl, "message": msg} for lvl, msg in analyse_cross_origin_headers(headers_cf)])
    findings.extend([{"level": lvl, "message": msg} for lvl, msg in analyse_x_dns_prefetch(get_header(headers_cf, "X-DNS-Prefetch-Control"))])
    findings.extend([{"level": lvl, "message": msg} for lvl, msg in analyse_x_permitted_cross_domain_policies(get_header(headers_cf, "X-Permitted-Cross-Domain-Policies"))])
    findings.extend([{"level": lvl, "message": msg} for lvl, msg in analyse_clear_site_data(get_header(headers_cf, "Clear-Site-Data"))])

    score = compute_score(good_count, weak_count, missing_count)
    redirects = analyse_redirect_chain(response)

    references = []
    if target_type == "web":
        references.append("Reference: https://owasp.org/www-project-secure-headers/")
        references.append("Note: If Content-Security-Policy is present and uses 'frame-ancestors', this generally governs framing behaviour, and modern browsers may prioritise CSP over X-Frame-Options.")
        references.append("Note: Clear-Site-Data is primarily recommended for logout and session management to help clear browser-side data such as cache, cookies, and storage.")
    else:
        references.append("Reference: https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html")

    result = {
        "target": target_url,
        "final_url": response.url,
        "target_type": target_type,
        "http_method_used": method_used,
        "status_code": response.status_code,
        "server": response.headers.get("Server", "Not disclosed"),
        "notes": notes,
        "redirect_chain": redirects,
        "summary": {
            "good": good_count,
            "weak": weak_count,
            "missing": missing_count,
            "score": score
        },
        "implemented_headers": implemented,
        "deprecated_headers_found": deprecated_found,
        "misconfiguration_findings": findings,
        "response_headers": dict(response.headers),
        "references": references
    }

    return result


# ============================================================
# OUTPUT
# ============================================================
def print_result(result):
    print(colour("\n===============================================================", C.BLUE))
    print(colour("[REQUEST / RESPONSE SUMMARY]", C.BOLD + C.BLUE))
    print(colour("===============================================================\n", C.BLUE))
    print(f"{C.BOLD}Target URL:{C.RESET} {result['target']}")
    print(f"{C.BOLD}Final URL:{C.RESET}  {result['final_url']}")
    print(f"{C.BOLD}Status:{C.RESET}     {result['status_code']}")
    print(f"{C.BOLD}Server:{C.RESET}     {result['server']}")
    print(f"{C.BOLD}Target Type:{C.RESET} {result['target_type'].upper()}")
    print(f"{C.BOLD}Method Used:{C.RESET} {result['http_method_used']}")

    if result["notes"]:
        for n in result["notes"]:
            print(f"{warn('[NOTE]')} {n}")

    print(colour("\n===============================================================", C.BLUE))
    print(colour("[REDIRECT CHAIN]", C.BOLD + C.BLUE))
    print(colour("===============================================================\n", C.BLUE))
    for item in result["redirect_chain"]:
        print(f"{item['status_code']} -> {item['url']}" + (f"  [Location: {item['location']}]" if item['location'] else ""))

    print(colour("\n===============================================================", C.BLUE))
    print(colour("[SECURITY HEADER ANALYSIS]", C.BOLD + C.BLUE))
    print(colour("===============================================================\n", C.BLUE))
    for h in result["implemented_headers"]:
        if h["status"] == "good":
            print(f"{good('[GOOD]')} {h['header']}: {h['value']}")
        elif h["status"] == "weak":
            print(f"{warn('[WEAK]')} {h['header']}: {h['value']}")
        else:
            print(f"{bad('[MISSING]')} {h['header']}")

    print(colour("\n===============================================================", C.BLUE))
    print(colour("[DEPRECATED HEADER REVIEW]", C.BOLD + C.BLUE))
    print(colour("===============================================================\n", C.BLUE))
    if result["deprecated_headers_found"]:
        for h in result["deprecated_headers_found"]:
            print(f"{warn('[DEPRECATED]')} {h['header']}: {h['value']}")
    else:
        print(good("[GOOD] No deprecated headers were identified in the response."))

    print(colour("\n===============================================================", C.BLUE))
    print(colour("[MISCONFIGURATION ANALYSIS]", C.BOLD + C.BLUE))
    print(colour("===============================================================\n", C.BLUE))
    if result["misconfiguration_findings"]:
        for f in result["misconfiguration_findings"]:
            if f["level"] == "warning":
                print(f"{warn('[WARNING]')} {f['message']}")
            else:
                print(f"{info('[INFO]')} {f['message']}")
    else:
        print(good("[GOOD] No obvious header misconfigurations were identified based on the implemented checks."))

    print(colour("\n===============================================================", C.BLUE))
    print(colour("[SUMMARY]", C.BOLD + C.BLUE))
    print(colour("===============================================================\n", C.BLUE))
    print(f"{good('[GOOD]')} Implemented / reasonably configured headers: {result['summary']['good']}")
    print(f"{warn('[WEAK]')} Implemented but potentially weak/misconfigured headers: {result['summary']['weak']}")
    print(f"{bad('[MISSING]')} Missing recommended headers: {result['summary']['missing']}")

    score = result["summary"]["score"]
    if score >= 80:
        s = good(f"{score}%")
    elif score >= 50:
        s = warn(f"{score}%")
    else:
        s = bad(f"{score}%")

    print(f"{C.BOLD}Security Header Coverage Score:{C.RESET} {s}")

    print(colour("\n===============================================================", C.BLUE))
    print(colour("[REFERENCE NOTES]", C.BOLD + C.BLUE))
    print(colour("===============================================================\n", C.BLUE))
    for ref in result["references"]:
        print(ref)

    print(colour("\n===============================================================", C.BLUE))
    print(colour("[PRESENT RESPONSE HEADERS]", C.BOLD + C.BLUE))
    print(colour("===============================================================\n", C.BLUE))
    for k, v in result["response_headers"].items():
        print(f"{C.BOLD}{k}:{C.RESET} {v}")


def build_html_report(results):
    rows = []
    for r in results:
        headers_html = "".join(
            f"<tr><td>{html.escape(h['header'])}</td><td>{html.escape(h['status'])}</td><td>{html.escape(str(h['value'])) if h['value'] is not None else ''}</td></tr>"
            for h in r["implemented_headers"]
        )
        deprecated_html = "".join(
            f"<li><b>{html.escape(h['header'])}</b>: {html.escape(str(h['value']))}</li>"
            for h in r["deprecated_headers_found"]
        ) or "<li>None identified</li>"
        findings_html = "".join(
            f"<li><b>{html.escape(f['level'].upper())}</b>: {html.escape(f['message'])}</li>"
            for f in r["misconfiguration_findings"]
        ) or "<li>No obvious misconfigurations identified.</li>"
        redirects_html = "".join(
            f"<li>{html.escape(str(x['status_code']))} - {html.escape(x['url'])}</li>"
            for x in r["redirect_chain"]
        )

        score = r["summary"]["score"]
        if score >= 80:
            score_class = "good"
        elif score >= 50:
            score_class = "warn"
        else:
            score_class = "bad"

        rows.append(f"""
        <div class="card">
          <h2>{html.escape(r['target'])}</h2>
          <p><b>Final URL:</b> {html.escape(r['final_url'])}</p>
          <p><b>Status:</b> {html.escape(str(r['status_code']))}</p>
          <p><b>Target Type:</b> {html.escape(r['target_type'].upper())}</p>
          <p><b>Method Used:</b> {html.escape(r['http_method_used'])}</p>
          <p><b>Server:</b> {html.escape(r['server'])}</p>
          <p><b>Score:</b> <span class="{score_class}">{html.escape(str(score))}%</span></p>

          <h3>Redirect Chain</h3>
          <ul>{redirects_html}</ul>

          <h3>Security Headers</h3>
          <table>
            <tr><th>Header</th><th>Status</th><th>Value</th></tr>
            {headers_html}
          </table>

          <h3>Deprecated Headers</h3>
          <ul>{deprecated_html}</ul>

          <h3>Misconfiguration Findings</h3>
          <ul>{findings_html}</ul>

          <h3>References</h3>
          <ul>{"".join(f"<li>{html.escape(x)}</li>" for x in r["references"])}</ul>
        </div>
        """)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Security Header Analysis Version 2026 - by camp4</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      margin: 0;
      padding: 20px;
    }}
    h1, h2, h3 {{
      color: #93c5fd;
    }}
    .meta {{
      margin-bottom: 20px;
      color: #cbd5e1;
    }}
    .card {{
      background: #1e293b;
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: 0 0 12px rgba(0,0,0,0.3);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 10px;
    }}
    th, td {{
      border: 1px solid #334155;
      padding: 8px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background: #334155;
    }}
    .good {{
      color: #22c55e;
      font-weight: bold;
    }}
    .warn {{
      color: #facc15;
      font-weight: bold;
    }}
    .bad {{
      color: #ef4444;
      font-weight: bold;
    }}
    a {{
      color: #93c5fd;
    }}
  </style>
</head>
<body>
  <h1>Security Header Analysis Version 2026</h1>
  <div class="meta">by camp4<br>Generated: {html.escape(now)}</div>
  {''.join(rows)}
</body>
</html>
"""


# ============================================================
# MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="Security Header Analysis Version 2026 by camp4")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url", help="Single target URL / host / IP")
    target_group.add_argument("-f", "--file", help="File containing targets, one per line")

    parser.add_argument("-t", "--type", choices=["web", "api"], required=True, help="Target type")
    parser.add_argument("-H", "--header", action="append", help="Custom header, e.g. 'Authorization: Bearer abc'", default=[])
    parser.add_argument("-k", "--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--timeout", type=int, default=20, help="Request timeout in seconds")
    parser.add_argument("--method", choices=["auto", "GET", "HEAD"], default="auto", help="Request method strategy")
    parser.add_argument("--json-out", help="Write JSON results to file")
    parser.add_argument("--html-out", help="Write HTML report to file")
    args = parser.parse_args()

    print_banner()

    try:
        custom_headers = parse_header_args(args.header)
    except ValueError as e:
        print(bad(f"[!] {e}"))
        sys.exit(1)

    raw_targets = []
    if args.url:
        raw_targets = [args.url]
    elif args.file:
        try:
            raw_targets = load_targets_from_file(args.file)
        except Exception as e:
            print(bad(f"[!] Could not load target file: {e}"))
            sys.exit(1)

    results = []

    for raw_target in raw_targets:
        print(info(f"\n[+] Analysing target: {raw_target}"))
        try:
            target = normalise_url(raw_target)
        except ValueError as e:
            print(bad(f"[!] Skipping invalid target '{raw_target}': {e}"))
            continue

        try:
            response, method_used, notes = perform_request(
                url=target,
                headers=custom_headers,
                verify_tls=not args.insecure,
                timeout=args.timeout,
                force_method=args.method
            )
        except requests.exceptions.SSLError as e:
            print(bad(f"[!] TLS/SSL error for {target}: {e}"))
            continue
        except requests.exceptions.ConnectionError as e:
            print(bad(f"[!] Connection error for {target}: {e}"))
            continue
        except requests.exceptions.Timeout:
            print(bad(f"[!] Request timed out for {target}"))
            continue
        except requests.exceptions.RequestException as e:
            print(bad(f"[!] Request failed for {target}: {e}"))
            continue

        result = analyse_response(
            target_url=target,
            response=response,
            target_type=args.type,
            method_used=method_used,
            notes=notes
        )
        print_result(result)
        results.append(result)

    if not results:
        print(bad("[!] No successful results to export."))
        sys.exit(1)

    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            print(good(f"\n[+] JSON report written to: {args.json_out}"))
        except Exception as e:
            print(bad(f"[!] Failed to write JSON report: {e}"))

    if args.html_out:
        try:
            html_report = build_html_report(results)
            with open(args.html_out, "w", encoding="utf-8") as f:
                f.write(html_report)
            print(good(f"[+] HTML report written to: {args.html_out}"))
        except Exception as e:
            print(bad(f"[!] Failed to write HTML report: {e}"))

    print(good("\n[+] Analysis completed."))


if __name__ == "__main__":
    main()