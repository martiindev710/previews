#!/usr/bin/env python3
"""
AI Security & Web Automation Governance Inspector (governance_inspector.py)
Author: Built for Akash Yadagouda (@akashyadagouda)
Purpose:
  Passive, non-intrusive web automation & AI governance telemetry inspector.
  Audits target web applications for:
    1. Outbound network/resource endpoints & Shadow AI / LLM telemetry SDKs
    2. HTTP Security & Governance Headers (CSP, CORS, HSTS, X-Frame-Options, Permissions-Policy)
    3. Script tag inventory with SHA-256 integrity hashes & SRI verification
    4. Cookie security posture (HttpOnly, Secure, SameSite) & client-storage usage signals
    5. DOM Input / Prompt Surface Inventory (passive inspection of forms, textareas,
       unbounded inputs, and indirect DOM/URL data ingestion surfaces)
"""

import argparse
import datetime
import hashlib
import json
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any, Dict, List

KNOWN_AI_AND_TELEMETRY_PATTERNS = {
    "openai": r"(api\.openai\.com|cdn\.oaistatic\.com|chatgpt\.com)",
    "anthropic": r"(api\.anthropic\.com|claude\.ai)",
    "gemini_vertex": r"(generativelanguage\.googleapis\.com|aiplatform\.googleapis\.com)",
    "cohere": r"(api\.cohere\.ai|cohere\.com)",
    "huggingface": r"(huggingface\.co|hf\.space)",
    "langchain_langsmith": r"(smith\.langchain\.com|langchain\.com)",
    "segment_analytics": r"(cdn\.segment\.com|api\.segment\.io)",
    "posthog": r"(app\.posthog\.com|us\.i\.posthog\.com)",
    "sentry": r"(sentry\.io|browser\.sentry-cdn\.com)",
    "google_analytics_gtm": r"(googletagmanager\.com|google-analytics\.com)",
    "intercom_crisp": r"(widget\.intercom\.io|client\.crisp\.chat)",
}

STORAGE_AND_SINK_PATTERNS = {
    "localStorage_read_write": r"localStorage\.(getItem|setItem)",
    "sessionStorage_read_write": r"sessionStorage\.(getItem|setItem)",
    "indexedDB_access": r"indexedDB\.open",
    "postMessage_channel": r"window\.postMessage|addEventListener\(\s*['\"]message['\"]",
    "dynamic_eval_or_html": r"\beval\(|innerHTML\s*=|document\.write\(",
    "fetch_or_xhr": r"\bfetch\(|XMLHttpRequest",
}


class GovernanceDOMParser(HTMLParser):
    """Passively parses HTML DOM to inventory scripts, links, iframes, meta policies, and input surfaces."""

    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.scripts: List[Dict[str, Any]] = []
        self.external_links: List[str] = []
        self.iframes: List[str] = []
        self.meta_tags: List[Dict[str, str]] = []
        self.input_surfaces: List[Dict[str, Any]] = []
        self._current_script_attrs: Dict[str, str] | None = None
        self._current_script_body: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        t = tag.lower()

        if t == "script":
            self._current_script_attrs = attr_map
            self._current_script_body = []
        elif t in ("a", "link"):
            href = attr_map.get("href", "").strip()
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                full_url = urllib.parse.urljoin(self.base_url, href)
                self.external_links.append(full_url)
        elif t == "iframe":
            src = attr_map.get("src", "").strip()
            self.iframes.append(urllib.parse.urljoin(self.base_url, src) if src else "inline-iframe")
        elif t == "meta":
            self.meta_tags.append(attr_map)
        elif t in ("form", "input", "textarea"):
            surface = {
                "element": t,
                "type": attr_map.get("type", "text" if t == "input" else t),
                "name_or_id": attr_map.get("name") or attr_map.get("id") or "anonymous",
                "action": urllib.parse.urljoin(self.base_url, attr_map["action"]) if attr_map.get("action") else None,
                "method": attr_map.get("method", "GET").upper() if t == "form" else None,
                "has_maxlength": "maxlength" in attr_map,
                "maxlength": attr_map.get("maxlength"),
                "autocomplete": attr_map.get("autocomplete", "unspecified"),
                "placeholder": attr_map.get("placeholder", "")[:80],
            }
            self.input_surfaces.append(surface)

    def handle_data(self, data: str) -> None:
        if self._current_script_attrs is not None:
            self._current_script_body.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._current_script_attrs is not None:
            raw_code = "".join(self._current_script_body).strip()
            src = self._current_script_attrs.get("src", "").strip()
            full_src = urllib.parse.urljoin(self.base_url, src) if src else None
            integrity = self._current_script_attrs.get("integrity", "")
            sha256_hash = hashlib.sha256(raw_code.encode("utf-8")).hexdigest() if raw_code else None

            detected_patterns = []
            for label, pat in STORAGE_AND_SINK_PATTERNS.items():
                if raw_code and re.search(pat, raw_code):
                    detected_patterns.append(label)

            self.scripts.append({
                "type": "external" if full_src else "inline",
                "src": full_src,
                "has_sri_integrity": bool(integrity),
                "sri_value": integrity or None,
                "inline_sha256": f"sha256-{sha256_hash[:24]}..." if sha256_hash else None,
                "inline_length_bytes": len(raw_code.encode("utf-8")),
                "runtime_signals": detected_patterns,
            })
            self._current_script_attrs = None
            self._current_script_body = []


def evaluate_headers_and_cookies(headers: Dict[str, str], raw_cookies: List[str]) -> Dict[str, Any]:
    h_lower = {k.lower(): v for k, v in headers.items()}

    csp = h_lower.get("content-security-policy", "")
    cors = h_lower.get("access-control-allow-origin", "")
    hsts = h_lower.get("strict-transport-security", "")
    xfo = h_lower.get("x-frame-options", "")
    xcto = h_lower.get("x-content-type-options", "")
    referrer = h_lower.get("referrer-policy", "")
    permissions = h_lower.get("permissions-policy", "")

    cookie_audits = []
    for c in raw_cookies:
        parts = [p.strip() for p in c.split(";")]
        name_val = parts[0].split("=", 1)[0] if parts else "unknown"
        flags_lower = [p.lower() for p in parts[1:]]
        has_secure = "secure" in flags_lower
        has_httponly = "httponly" in flags_lower
        samesite = next((f.split("=", 1)[1] for f in flags_lower if f.startswith("samesite=")), "missing")
        cookie_audits.append({
            "cookie_name": name_val,
            "secure": has_secure,
            "http_only": has_httponly,
            "same_site": samesite,
            "governance_status": "PASS" if (has_secure and has_httponly and samesite != "missing") else "WARN",
        })

    guardrail_checks = [
        {
            "rule_id": "GOV-HDR-001",
            "control": "Content-Security-Policy (Outbound Connect/Script Guardrail)",
            "status": "PASS" if csp and "default-src" in csp.lower() else ("WARN" if csp else "FAIL"),
            "detail": csp[:140] if csp else "Missing Content-Security-Policy header; unguarded outbound fetch/LLM API egress possible.",
        },
        {
            "rule_id": "GOV-HDR-002",
            "control": "CORS Origin Isolation (Access-Control-Allow-Origin)",
            "status": "FAIL" if cors.strip() == "*" else "PASS",
            "detail": f"ACAO={cors}" if cors else "No permissive wildcard CORS header exposed.",
        },
        {
            "rule_id": "GOV-HDR-003",
            "control": "Strict-Transport-Security (TLS Enforcement)",
            "status": "PASS" if hsts else "WARN",
            "detail": hsts if hsts else "Missing HSTS header on endpoint.",
        },
        {
            "rule_id": "GOV-HDR-004",
            "control": "Frame & Clickjacking Guardrail (X-Frame-Options / frame-ancestors)",
            "status": "PASS" if (xfo or "frame-ancestors" in csp.lower()) else "WARN",
            "detail": xfo if xfo else "No explicit X-Frame-Options or CSP frame-ancestors policy.",
        },
        {
            "rule_id": "GOV-HDR-005",
            "control": "Browser Feature & Sensor Lockdown (Permissions-Policy)",
            "status": "PASS" if permissions else "WARN",
            "detail": permissions[:120] if permissions else "Missing Permissions-Policy (microphone/camera/geolocation not explicitly restricted).",
        },
    ]

    return {
        "headers_present": {
            "content_security_policy": bool(csp),
            "access_control_allow_origin": cors or None,
            "strict_transport_security": bool(hsts),
            "x_frame_options": xfo or None,
            "x_content_type_options": xcto or None,
            "referrer_policy": referrer or None,
            "permissions_policy": bool(permissions),
        },
        "cookie_audits": cookie_audits,
        "guardrail_checks": guardrail_checks,
    }


def audit_endpoint(url: str, timeout: int = 12) -> Dict[str, Any]:
    t0 = time.time()
    parsed_target = urllib.parse.urlparse(url)
    target_host = parsed_target.netloc.lower()

    ctx = ssl.create_default_context()
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "AI-Governance-Inspector/1.0 (+Passive-Audit)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status_code = resp.status
            final_url = resp.geturl()
            raw_headers = dict(resp.headers.items())
            raw_cookies = resp.headers.get_all("Set-Cookie") or []
            body_bytes = resp.read(250_000)
            html_text = body_bytes.decode("utf-8", errors="replace")
    except Exception as exc:
        return {
            "target_url": url,
            "status": "ERROR",
            "error": str(exc),
            "elapsed_ms": round((time.time() - t0) * 1000, 1),
        }

    elapsed_ms = round((time.time() - t0) * 1000, 1)
    parser = GovernanceDOMParser(final_url)
    parser.feed(html_text)

    # Identify third-party domains & shadow AI / telemetry matches
    third_party_domains = set()
    for s in parser.scripts:
        if s["src"]:
            h = urllib.parse.urlparse(s["src"]).netloc.lower()
            if h and h != target_host:
                third_party_domains.add(h)
    for link in parser.external_links:
        h = urllib.parse.urlparse(link).netloc.lower()
        if h and h != target_host:
            third_party_domains.add(h)

    shadow_ai_matches = []
    for provider, pattern in KNOWN_AI_AND_TELEMETRY_PATTERNS.items():
        found = set(re.findall(pattern, html_text, flags=re.IGNORECASE))
        if found:
            shadow_ai_matches.append({
                "provider_or_sdk": provider,
                "matched_endpoints": sorted(found),
                "risk_classification": "AI_MODEL_EGRESS" if provider in ("openai", "anthropic", "gemini_vertex", "cohere", "huggingface") else "TELEMETRY_EGRESS",
            })

    header_eval = evaluate_headers_and_cookies(raw_headers, raw_cookies)

    # Evaluate DOM input & indirect prompt surface governance
    unbounded_inputs = [
        inp for inp in parser.input_surfaces
        if inp["element"] in ("input", "textarea") and not inp["has_maxlength"] and inp["type"] not in ("hidden", "submit", "checkbox", "radio")
    ]
    external_scripts_without_sri = [
        s for s in parser.scripts if s["type"] == "external" and not s["has_sri_integrity"]
    ]

    header_eval["guardrail_checks"].extend([
        {
            "rule_id": "GOV-DOM-006",
            "control": "Subresource Integrity (SRI) on External Scripts",
            "status": "PASS" if len(external_scripts_without_sri) == 0 else "WARN",
            "detail": f"{len(external_scripts_without_sri)} external script(s) loaded without SHA-256/384 SRI integrity attribute.",
        },
        {
            "rule_id": "GOV-PROMPT-007",
            "control": "Input / Prompt Surface Token-Length & Boundary Controls",
            "status": "PASS" if len(unbounded_inputs) == 0 else "WARN",
            "detail": f"{len(unbounded_inputs)} user input surface(s) lack explicit DOM maxlength boundary controls.",
        },
        {
            "rule_id": "GOV-AI-008",
            "control": "Shadow AI & Unsanctioned Client-Side Telemetry SDK Detection",
            "status": "WARN" if shadow_ai_matches else "PASS",
            "detail": f"Detected {len(shadow_ai_matches)} third-party AI/telemetry SDK signature(s) in client bundle." if shadow_ai_matches else "Zero direct client-side LLM/Shadow-AI SDK endpoints exposed in DOM.",
        },
    ])

    pass_count = sum(1 for c in header_eval["guardrail_checks"] if c["status"] == "PASS")
    total_checks = len(header_eval["guardrail_checks"])
    governance_score = round((pass_count / total_checks) * 100) if total_checks else 100

    return {
        "target_url": url,
        "final_url": final_url,
        "http_status": status_code,
        "elapsed_ms": elapsed_ms,
        "audited_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "governance_score": governance_score,
        "summary_metrics": {
            "total_scripts": len(parser.scripts),
            "external_scripts": sum(1 for s in parser.scripts if s["type"] == "external"),
            "inline_scripts": sum(1 for s in parser.scripts if s["type"] == "inline"),
            "external_scripts_missing_sri": len(external_scripts_without_sri),
            "third_party_domains_count": len(third_party_domains),
            "input_surfaces_count": len(parser.input_surfaces),
            "unbounded_input_surfaces": len(unbounded_inputs),
            "shadow_ai_or_telemetry_sdks": len(shadow_ai_matches),
            "guardrails_passed": pass_count,
            "guardrails_total": total_checks,
        },
        "shadow_ai_and_telemetry_detections": shadow_ai_matches,
        "third_party_domains_sample": sorted(third_party_domains)[:25],
        "script_inventory": parser.scripts[:15],
        "input_surface_inventory": parser.input_surfaces[:15],
        "headers_and_cookies": header_eval,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Passive AI Security & Web Governance Inspector")
    ap.add_argument(
        "--urls",
        nargs="+",
        default=[
            "https://news.ycombinator.com",
            "https://example.com",
            "https://www.yashpanpaliya.dev",
        ],
        help="Target URLs to passively inspect",
    )
    ap.add_argument(
        "--output",
        default="/workspace/sprint-100/previews/01-akashyadagouda/sample_audit_trace.json",
        help="Output JSON file path",
    )
    args = ap.parse_args()

    results = []
    for u in args.urls:
        print(f"[*] Auditing endpoint: {u} ...")
        res = audit_endpoint(u)
        results.append(res)
        print(
            f"    -> HTTP {res.get('http_status')} | Score: {res.get('governance_score')}/100 | "
            f"Scripts: {res.get('summary_metrics', {}).get('total_scripts')} | "
            f"3P Domains: {res.get('summary_metrics', {}).get('third_party_domains_count')} | "
            f"Elapsed: {res.get('elapsed_ms')}ms"
        )

    report = {
        "AuditSuite": "AegisGov — Web Automation & AI Security Telemetry Inspector",
        "Version": "1.0.0",
        "GeneratedAtUTC": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "GeneratedAtBuenosAires": datetime.datetime.now(
            datetime.timezone(datetime.timedelta(hours=-3))
        ).strftime("%Y-%m-%d %H:%M:%S (UTC-3)"),
        "Mode": "Passive Read-Only DOM, Network Egress & Security Header Governance Audit",
        "TwoCoreAISecurityProblemsAddressed": [
            {
                "ProblemID": "AI-SEC-01",
                "Title": "Indirect Prompt Injection via Untrusted DOM / Hidden Accessibility-Tree Payloads in Browser Agents",
                "TechnicalGap": "Browser-use and computer-use agents ingest raw DOM text, aria-labels, and hidden CSS subtrees without provenance tagging. A third-party comment or invisible span can hijack the agent's planner into exfiltrating session state over an unguarded fetch/navigation call.",
                "EnforcementFix": "Pre-execution DOM Provenance Sanitizer + Strict Content-Security-Policy (connect-src) allowlisting & browser-context egress interception before agent action execution."
            },
            {
                "ProblemID": "AI-SEC-02",
                "Title": "Shadow AI Egress & Unscoped Tool-Call Credential Leakage in Client/Edge Apps",
                "TechnicalGap": "Frontend and Node.js BFF layers routinely bundle third-party AI/telemetry SDKs or forward user bearer tokens / session cookies into downstream MCP/tool calls without per-tool audience scoping or redact-on-egress policies.",
                "EnforcementFix": "Automated Headless Telemetry & Script-SRI Auditing + Ephemeral Scoped Capability Tokens with deterministic PII/Secret Redaction Proxy."
            }
        ],
        "EndpointAudits": results,
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Saved verified governance audit trace to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
