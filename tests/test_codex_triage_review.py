from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
import tempfile
from unittest import TestCase
from unittest.mock import patch


def _load_module():
    module_path = Path(__file__).resolve().parents[1] / "scripts" / "codex_triage_review.py"
    spec = importlib.util.spec_from_file_location("codex_triage_review_script", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load scripts/codex_triage_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CodexTriageReviewTests(TestCase):
    def test_run_codex_uses_read_only_noninteractive_execution(self) -> None:
        module = _load_module()
        payload = {
            "schema_version": 1,
            "kind": "new_cve_context_review_request",
            "candidates": [
                {
                    "vuln_id": "CVE-2026-0005",
                    "signals": [],
                    "cvss": 10.0,
                    "epss": 0,
                }
            ],
        }

        def fake_run(cmd, **kwargs):
            output_path = Path(cmd[cmd.index("--output-last-message") + 1])
            output_path.write_text(
                '{"schema_version":1,"kind":"new_cve_context_review_response",'
                '"reviews":[{"vuln_id":"CVE-2026-0005","decision":"suppress",'
                '"confidence":"low","reason":"CVSS-only without stronger signal"}]}',
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "llm_reviews"
            with (
                patch.object(module, "DEFAULT_LOG_DIR", log_dir),
                patch.object(module.subprocess, "run", side_effect=fake_run) as run,
            ):
                response = module.run_codex(payload, "codex", None, 30)

            logs = sorted(log_dir.glob("*.json"))
            self.assertEqual(1, len(logs))
            log = logs[0].read_text(encoding="utf-8")
            self.assertIn("codex_triage_review_log", log)
            self.assertIn("CVE-2026-0005", log)

        cmd = run.call_args.args[0]
        env = run.call_args.kwargs["env"]
        self.assertIn("exec", cmd)
        self.assertIn("--sandbox", cmd)
        self.assertIn("read-only", cmd)
        self.assertIn("-a", cmd)
        self.assertIn("never", cmd)
        self.assertIn("--ephemeral", cmd)
        self.assertIn("CODEX_HOME", env)
        self.assertTrue(env["CODEX_HOME"].startswith("/tmp/vulnsignal-codex-home-"))
        self.assertEqual("new_cve_context_review_response", response["kind"])
        self.assertEqual("suppress", response["reviews"][0]["decision"])

    def test_normalize_response_drops_invalid_reviews(self) -> None:
        module = _load_module()
        response = module._normalize_response(
            {
                "reviews": [
                    {
                        "vuln_id": "CVE-2026-0001",
                        "decision": "watch_now",
                        "confidence": "certain",
                        "reason": "exploit-backed",
                    },
                    {
                        "vuln_id": "CVE-2026-0002",
                        "decision": "invalid",
                        "confidence": "low",
                        "reason": "bad decision",
                    },
                ]
            }
        )

        self.assertEqual(1, len(response["reviews"]))
        self.assertEqual("medium", response["reviews"][0]["confidence"])

    def test_prompt_defines_operational_watchlist_expectations(self) -> None:
        module = _load_module()
        prompt = module._build_prompt(
            {
                "schema_version": 1,
                "kind": "new_cve_context_review_request",
                "candidates": [],
            }
        )

        self.assertIn("A short, high-signal operational watchlist", prompt)
        self.assertIn("watch_now", prompt)
        self.assertIn("monitor_only", prompt)
        self.assertIn("suppress", prompt)
        self.assertIn("Review every candidate", prompt)
        self.assertIn("signal + operational relevance", prompt)
        self.assertIn("old CVEs that became newly hot", prompt)
        self.assertIn("named or campaign-like vulnerabilities", prompt)
        self.assertIn("Supply-chain and developer endpoint risk", prompt)
        self.assertIn("Default suppress categories", prompt)
