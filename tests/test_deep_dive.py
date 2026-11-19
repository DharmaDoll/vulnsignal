from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from sync.exploit_adapter import ExploitRecord


def _load_deep_dive_module():
    module_path = Path(__file__).resolve().parents[1] / "scripts" / "deep_dive.py"
    spec = importlib.util.spec_from_file_location("deep_dive_script", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load scripts/deep_dive.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DeepDiveContractTests(TestCase):
    def test_build_report_emits_versioned_contract(self) -> None:
        module = _load_deep_dive_module()

        core_stub = {
            "vulnerability": {"title": "Sample title"},
            "signals": {"kev": {"observed_at": "2026-06-26T00:00:00Z"}, "hot": {}},
            "has_exploit": True,
        }
        exploit = ExploitRecord(
            vuln_id="CVE-2026-31431",
            source="go-exploitdb",
            exploit_type="poc",
            url="https://example.invalid/exploit",
            observed_at="2026-06-26T00:00:00Z",
            exploit_unique_id="GitHub-example",
            description="Sample exploit",
        )

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "core.db"
            exploit_db = Path(tmp) / "exploit.db"

            exploit_db.touch()
            with (
                patch.object(module, "migrate", return_value=None),
                patch.object(module, "utc_now", return_value="2026-06-26T00:00:00Z"),
                patch.object(module, "source_context", return_value=(core_stub, [])),
                patch.object(module, "get_exploits", return_value=[exploit]),
            ):
                report = module.build_report(
                    vuln_id="CVE-2026-31431",
                    db_path=db_path,
                    exploit_db=exploit_db,
                )

        self.assertEqual(2, report["schema_version"])
        self.assertEqual([], report["package_advisories"])
        self.assertEqual("deep_dive", report["kind"])
        self.assertEqual("CVE-2026-31431", report["vuln_id"])
        self.assertEqual("2026-06-26T00:00:00Z", report["generated_at"])
        self.assertEqual(str(db_path), report["sources"]["core_db"])
        self.assertEqual(str(exploit_db), report["sources"]["exploit_db"])
        self.assertEqual(core_stub, report["core"])
        self.assertEqual(1, len(report["go_exploitdb"]))
        self.assertEqual("go-exploitdb", report["go_exploitdb"][0]["source"])
        self.assertEqual(1, len(report["hot"]))
        self.assertIsNone(report["hot_refresh"])
        self.assertEqual("watch_now", report["impact"]["priority"])
        self.assertIn("affected_conditions", report["impact"])
        self.assertIn("not_affected_conditions", report["impact"])
        self.assertIn("verification_steps", report["impact"])
        self.assertIn("immediate_mitigation", report["impact"])
        self.assertIn("permanent_fix", report["impact"])
        self.assertIn("detection_guidance", report["impact"])
        self.assertIn("residual_risk", report["impact"])
        self.assertEqual(["hot", "kev"], report["impact"]["evidence"]["signals"])
