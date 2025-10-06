import os
import json
import re
import logging
from typing import Any, Dict, Optional
from openai import OpenAI
from dotenv import load_dotenv
from datetime import datetime, timezone

load_dotenv()
logger = logging.getLogger(__name__)

client = OpenAI(
    base_url=os.getenv("LLM_BASE_URL", "https://router.huggingface.co/v1"),
    api_key=os.getenv("HF_TOKEN")
)

def datetime_iso_now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat()

def _safe_json_load(s: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(s)
    except Exception:
        pass
    json_match = re.search(r"\{(?:[^{}]|(?R))*\}", s, flags=re.DOTALL)
    if not json_match:
        try:
            start = s.index("{")
            end = s.rindex("}")
            candidate = s[start:end + 1]
            return json.loads(candidate)
        except Exception:
            return None
    try:
        return json.loads(json_match.group(0))
    except Exception:
        return None

def call_llm(
    scan_results: Dict[str, Any],
    model: str = "meta-llama/Llama-3.1-8B-Instruct:cerebras",
    max_tokens: int = 9000,
    temperature: float = 0.25,
    debug: bool = False
) -> Dict[str, Any]:
    base_prompt = """
You are a senior cybersecurity analyst and technical writer specializing in transforming
raw scanner or reconnaissance tool outputs into comprehensive, technically detailed,
and human-readable vulnerability reports suitable for both developers and security teams.

### OBJECTIVE:
Given raw results from one or more security tools, your job is to:
1. Interpret and normalize the findings.
2. Extract all relevant technical and contextual information about each vulnerability or misconfiguration.
3. Provide in-depth analysis covering how it works, potential exploitation paths, affected components, and mitigations.
4. Produce a complete, structured, and machine-parseable JSON report that maintains technical precision and readability.

### YOU MUST EXTRACT & EXPLAIN TECHNICAL DETAILS INCLUDING:
- Vulnerability type and CWE / CVE reference if identifiable.
- Attack vector (network, local, web, API, etc.).
- Root cause (injection, misconfiguration, weak crypto, etc.).
- Impact (data disclosure, privilege escalation, remote execution, DoS, etc.).
- Affected components (endpoint, parameter, token, port, service, header, file, etc.).
- How the issue can be exploited (include step summary or example payload if known).
- Detection method (tool name, evidence, command or scan pattern).
- Severity classification and justification.
- Detailed remediation plan including secure configuration, patch, or code fix.
- Any interdependencies, chained vulnerabilities, or related risks.
- Risk likelihood and estimated business/technical impact.

If multiple scanners or tools are involved, correlate and combine overlapping findings.

### STRICT JSON OUTPUT FORMAT (no markdown, no text outside JSON):
{
  "summary": "Concise plain-English overview of key vulnerabilities and system risk.",
  "criticality": {
    "overall_level": "<Low | Medium | High | Critical>",
    "rationale": "Explain why this severity level was chosen."
  },
  "actions": [
    "Immediate action 1",
    "Action 2",
    "Action 3"
  ],
  "detailed_report": [
    {
      "title": "Vulnerability title (e.g., SQL Injection in /login endpoint)",
      "cwe_id": "CWE-89 (if applicable)",
      "cve_id": "CVE-2023-XXXX (if applicable)",
      "severity": "<Low | Medium | High | Critical>",
      "attack_vector": "e.g., Network, Web, Local, API, Authentication Bypass, etc.",
      "affected_components": [
        "e.g., /login parameter 'username'",
        "e.g., Port 443 (HTTPS)"
      ],
      "evidence": "Raw indicator or snippet from scan result that confirms the finding.",
      "technical_analysis": "Deep technical explanation of how the vulnerability works, exploitation mechanism, and why it is dangerous.",
      "impact": "Detailed explanation of potential outcomes — data loss, privilege escalation, RCE, DoS, etc.",
      "root_cause": "Underlying flaw or misconfiguration causing the vulnerability.",
      "exploitation_scenario": "Example attack flow or exploitation steps.",
      "detection_source": "Tool(s) or method(s) that identified the issue.",
      "related_vulnerabilities": [
        "Mention related issues, CVEs, or chained exploits."
      ],
      "remediation": "Precise, technically correct fix steps (patch version, config, code fix, etc.).",
      "references": [
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://owasp.org/www-project-top-ten/"
      ]
    }
  ],
  "meta": {
    "generated_at": "<ISO-8601 timestamp>",
    "scan_origin_summary": "Summary of tools or scan sources used.",
    "confidence_score": "<0.0–1.0>"
  }
}

### REPORTING RULES:
- Output valid JSON only.
- Include reasoning for severity.
- Use "N/A" where data is unavailable.
- Maintain professional and factual tone.
- If uncertain, confidence_score < 0.7.
- The output should resemble an enterprise-grade pentest report.
"""

    prompt = f"""{base_prompt}

Scan results (JSON):
{json.dumps(scan_results, indent=2)}

Produce the JSON response exactly in the format above and nothing else.
"""

    if debug:
        logger.debug("Prompt sent to LLM:\n" + prompt[:4000])

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=temperature,
        )
        try:
            raw = response.choices[0].message.content
        except Exception:
            raw = str(response)
        parsed = _safe_json_load(raw)
        if parsed is None:
            logger.warning("LLM output could not be parsed as JSON. Returning raw output.")
            return {"parsed": None, "raw": raw, "error": "failed_to_parse_json"}
        required_keys = ["summary", "criticality", "actions", "detailed_report", "meta"]
        for key in required_keys:
            parsed.setdefault(key, "N/A")
        if isinstance(parsed.get("meta"), dict):
            parsed["meta"].setdefault("generated_at", datetime_iso_now())
            parsed["meta"].setdefault("scan_origin_summary", "")
            parsed["meta"].setdefault("confidence_score", "N/A")
        else:
            parsed["meta"] = {
                "generated_at": datetime_iso_now(),
                "scan_origin_summary": "",
                "confidence_score": "N/A",
            }
        return {"parsed": parsed, "raw": raw, "error": None}
    except Exception as e:
        logger.exception("LLM call failed")
        return {"parsed": None, "raw": None, "error": str(e)}
