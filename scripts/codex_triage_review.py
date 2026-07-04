#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RESPONSE_KIND = "new_cve_context_review_response"
SCHEMA_VERSION = 1
DEFAULT_LOG_DIR = ROOT / "data" / "reports" / "triage" / "llm_reviews"


RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "kind", "reviews"],
    "properties": {
        "schema_version": {"type": "integer", "const": SCHEMA_VERSION},
        "kind": {"type": "string", "const": RESPONSE_KIND},
        "reviews": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["vuln_id", "decision", "confidence", "reason"],
                "properties": {
                    "vuln_id": {"type": "string", "pattern": "^CVE-\\d{4}-\\d+$"},
                    "decision": {"type": "string", "enum": ["watch_now", "monitor_only", "suppress"]},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                    "reason": {"type": "string", "minLength": 1, "maxLength": 240},
                },
            },
        },
    },
}


def _load_payload() -> dict[str, Any]:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"stdin must be JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("stdin JSON must be an object")
    return payload


def _build_prompt(payload: dict[str, Any]) -> str:
    return "\n".join(
        [
            "You are the bounded context reviewer for vulnsignal new-CVE triage.",
            "",
            "Goal:",
            "Read the supplied local-only candidate JSON and decide whether each CVE deserves human attention now.",
            "",
            "What vulnsignal wants:",
            "- A short, high-signal operational watchlist, not a complete CVE catalog.",
            "- Items that are likely to matter to real remediation workflows within days.",
            "- Prefer vulnerabilities with exploitation, active attention, high exploit probability, or broad operational blast radius.",
            "- Suppress noise from plain recency, title severity, niche plugins, and CVSS-only records unless there is a concrete reason to monitor.",
            "- Treat old CVEs that became newly hot as relevant only when the supplied hot/exploit/KEV context explains why they matter now.",
            "- Preserve named or campaign-like vulnerabilities when the input indicates a widely discussed nickname, branded issue, coordinated disclosure, mass-exploitation wave, or supply-chain pattern.",
            "",
            "Priority categories:",
            "- Internet-facing remote code execution, auth bypass, privilege escalation, file upload, deserialization, template injection, path traversal to code execution, or security-control bypass.",
            "- Cloud and edge infrastructure: AWS/Azure/GCP control plane or edge services, WAF/CDN/load balancer, identity/auth, VPN, SSO, API gateway, managed Kubernetes, container runtime, CI/CD, artifact registry, package manager, developer tooling, and widely used OSS libraries/frameworks.",
            "- Supply-chain and developer endpoint risk: package installer/toolchain compromise, dependency confusion/typosquatting class, signed artifact bypass, CI secrets exposure, GitHub/GitLab runner impact, or local developer workstation compromise with realistic path to code or credential theft.",
            "- Enterprise operational breadth: software commonly deployed across many organizations, managed services, infrastructure components, security products, observability/logging agents, databases, message queues, and web frameworks.",
            "",
            "Default suppress categories:",
            "- Niche WordPress/CMS/plugin issues with no exploit, KEV, hot, high EPSS, or broad deployment clue.",
            "- Local-only DoS/crash, UI-only bug, authenticated low-privilege nuisance, or physical/local access issue without escalation path.",
            "- Narrow vendor appliance issues unless KEV/exploit/hot/high EPSS is present or the title implies internet-facing perimeter impact.",
            "- CVSS-only records where the title is severe but the supplied context gives no exploitability, prevalence, active attention, or remediation urgency.",
            "",
            "Decision policy:",
            "- watch_now: use when there is KEV, exploit evidence, credible hot evidence, EPSS >= 0.05, or a broadly deployed internet-facing/cloud/dev-tool component with severe unauthenticated RCE/auth-bypass/privilege-escalation impact.",
            "- monitor_only: use for severe but unproven issues in important ecosystems, cloud/SaaS infrastructure, developer tooling, CI/CD, identity/auth, container/Kubernetes, web frameworks, or widely deployed libraries.",
            "- suppress: use for CVSS-only records with no KEV, exploit, hot, high EPSS, or clear broad operational relevance; especially niche WordPress/CMS plugins, local-only DoS, narrow vendor appliances, or vague titles without actionable context.",
            "",
            "Hot evidence policy:",
            "- credible hot means multiple relevant URLs/domains, exploit/Poc/patch-bypass/vendor-advisory discussion, or a high attention score with security-focused sources.",
            "- weak hot means a single generic news mention, mirrored CVE page, SEO/content-farm result, or unrelated search hit.",
            "",
            "Reason requirements:",
            "- Explain the decision using signal + operational relevance.",
            "- For suppress, state the missing signal or why the scope is too narrow.",
            "- For monitor_only, state what would promote it to watch_now.",
            "- Keep the reason short but specific.",
            "",
            "Rules:",
            "- Use only the JSON input below.",
            "- Do not browse the web.",
            "- Do not run shell commands.",
            "- Do not modify files or databases.",
            "- Do not invent asset impact.",
            "- Review every candidate in the input.",
            "- Do not suppress KEV or exploit-backed candidates.",
            "- Do not classify broad relevance from brand recognition alone; tie it to the supplied title, signals, or context.",
            "- Return JSON only. No markdown. No commentary.",
            "",
            "Input JSON:",
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
        ]
    )


def _extract_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if not stripped:
        raise ValueError("Codex returned an empty response")
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", stripped, flags=re.DOTALL)
        if not match:
            raise
        parsed = json.loads(match.group(0))
    if not isinstance(parsed, dict):
        raise ValueError("Codex response must be a JSON object")
    return parsed


def _seed_codex_home(target_home: Path) -> None:
    source_home = Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
    for name in ("auth.json", "config.toml"):
        source = source_home / name
        if source.exists():
            target = target_home / name
            if target.exists() or target.is_symlink():
                target.unlink()
            target.symlink_to(source)


def _payload_summary(payload: dict[str, Any]) -> dict[str, Any]:
    candidates = payload.get("candidates")
    vuln_ids = []
    if isinstance(candidates, list):
        vuln_ids = [
            str(candidate.get("vuln_id") or "")
            for candidate in candidates
            if isinstance(candidate, dict) and candidate.get("vuln_id")
        ]
    return {
        "schema_version": payload.get("schema_version"),
        "kind": payload.get("kind"),
        "cutoff": payload.get("cutoff"),
        "candidate_count": len(vuln_ids),
        "vuln_ids": vuln_ids,
    }


def _write_log_file(
    log_dir: Path,
    started_at: datetime,
    payload: dict[str, Any],
    prompt: str,
    cmd: list[str],
    returncode: int,
    stdout: str,
    stderr: str,
    response: dict[str, Any] | None,
    error: str | None,
) -> Path:
    log_dir.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    digest.update(prompt.encode("utf-8"))
    digest.update(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8"))
    name = f"{started_at.strftime('%Y%m%dT%H%M%SZ')}-{digest.hexdigest()[:8]}.json"
    path = log_dir / name
    record = {
        "schema_version": 1,
        "kind": "codex_triage_review_log",
        "started_at": started_at.isoformat(timespec="seconds"),
        "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "command": cmd,
        "returncode": returncode,
        "payload_summary": _payload_summary(payload),
        "prompt": prompt,
        "stdout": stdout,
        "stderr": stderr,
        "response": response,
        "error": error,
    }
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def _normalize_response(response: dict[str, Any]) -> dict[str, Any]:
    reviews = response.get("reviews")
    if not isinstance(reviews, list):
        reviews = []
    normalized_reviews: list[dict[str, Any]] = []
    for review in reviews:
        if not isinstance(review, dict):
            continue
        vuln_id = str(review.get("vuln_id") or "")
        decision = str(review.get("decision") or "")
        confidence = str(review.get("confidence") or "")
        reason = str(review.get("reason") or "").strip()
        if decision not in {"watch_now", "monitor_only", "suppress"}:
            continue
        if confidence not in {"high", "medium", "low"}:
            confidence = "medium"
        if not vuln_id or not reason:
            continue
        normalized_reviews.append(
            {
                "vuln_id": vuln_id,
                "decision": decision,
                "confidence": confidence,
                "reason": reason[:240],
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": RESPONSE_KIND,
        "reviews": normalized_reviews,
    }


def run_codex(
    payload: dict[str, Any],
    codex_binary: str,
    model: str | None,
    timeout: int,
    log_dir: Path | None = None,
) -> dict[str, Any]:
    prompt = _build_prompt(payload)
    started_at = datetime.now(timezone.utc)
    log_dir = log_dir or DEFAULT_LOG_DIR
    with tempfile.TemporaryDirectory(prefix="vulnsignal-codex-review-") as tmp_dir, tempfile.TemporaryDirectory(
        prefix="vulnsignal-codex-home-"
    ) as home_dir:
        tmp = Path(tmp_dir)
        codex_home = Path(home_dir)
        _seed_codex_home(codex_home)
        schema_path = tmp / "response.schema.json"
        output_path = tmp / "response.json"
        schema_path.write_text(json.dumps(RESPONSE_SCHEMA, indent=2), encoding="utf-8")

        cmd = [
            codex_binary,
            "-a",
            "never",
            "exec",
            "--cd",
            str(ROOT),
            "--sandbox",
            "read-only",
            "--ephemeral",
            "--output-schema",
            str(schema_path),
            "--output-last-message",
            str(output_path),
        ]
        if model:
            cmd.extend(["--model", model])
        cmd.append(prompt)

        env = os.environ.copy()
        env["CODEX_HOME"] = str(codex_home)
        env.setdefault("NO_COLOR", "1")
        completed = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False, env=env)
        output = output_path.read_text(encoding="utf-8") if output_path.exists() else completed.stdout
        try:
            response = _normalize_response(_extract_json(output))
        except Exception as exc:
            _write_log_file(
                log_dir=log_dir,
                started_at=started_at,
                payload=payload,
                prompt=prompt,
                cmd=cmd,
                returncode=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                response=None,
                error=str(exc),
            )
            raise RuntimeError(completed.stderr.strip() or str(exc)) from exc
        _write_log_file(
            log_dir=log_dir,
            started_at=started_at,
            payload=payload,
            prompt=prompt,
            cmd=cmd,
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            response=response,
            error=None if completed.returncode == 0 else completed.stderr.strip() or f"codex exited with {completed.returncode}",
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or f"codex exited with {completed.returncode}")
    return response


def main() -> int:
    parser = argparse.ArgumentParser(description="Review new-CVE triage candidates with Codex.")
    parser.add_argument("--codex-binary", default="codex")
    parser.add_argument("--model")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument(
        "--print-prompt",
        action="store_true",
        help="Print the generated Codex prompt instead of invoking Codex.",
    )
    args = parser.parse_args()

    payload = _load_payload()
    if args.print_prompt:
        print(_build_prompt(payload))
        return 0

    try:
        response = run_codex(payload, args.codex_binary, args.model, args.timeout)
    except Exception as exc:
        print(f"codex triage review failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(response, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
