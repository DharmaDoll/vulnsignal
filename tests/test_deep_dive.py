from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from sync.exploit_adapter import ExploitRecord
from sync.trivy_adapter import AdvisoryRecord


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
            "signals": {"kev": {"observed_at": "2026-06-26T00:00:00Z"}},
            "has_exploit": True,
        }
        advisory = AdvisoryRecord(
            vuln_id="CVE-2026-31431",
            source="ubuntu",
            ecosystem="ubuntu",
            package_name="linux",
            affected_versions=["released:jammy:5.15.0-179.189"],
            fixed_version="7.0~rc7, 6.8.y, 6.17.y",
            severity="high",
            observed_at="2026-06-26T00:00:00Z",
            published_at="2026-04-22T09:16:00Z",
            source_path="/tmp/source.json",
            title="Sample advisory",
            summary="Sample advisory summary",
            references=["https://example.invalid/advisory"],
        )
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
            mirror_dir = Path(tmp) / "mirror"
            exploit_db = Path(tmp) / "exploit.db"

            with (
                patch.object(module, "migrate", return_value=None),
                patch.object(module, "utc_now", return_value="2026-06-26T00:00:00Z"),
                patch.object(module.skills, "find_vuln", return_value=core_stub),
                patch.object(module.skills, "top_hot", return_value=[{"vuln_id": "CVE-2026-31431"}]),
                patch.object(module, "load_advisories_for_vuln_id_from_directory", return_value=[advisory]),
                patch.object(module, "get_exploits", return_value=[exploit]),
            ):
                report = module.build_report(
                    vuln_id="CVE-2026-31431",
                    db_path=db_path,
                    mirror_dir=mirror_dir,
                    exploit_db=exploit_db,
                )

        self.assertEqual(1, report["schema_version"])
        self.assertEqual("deep_dive", report["kind"])
        self.assertEqual("CVE-2026-31431", report["vuln_id"])
        self.assertEqual("2026-06-26T00:00:00Z", report["generated_at"])
        self.assertEqual(str(db_path), report["sources"]["core_db"])
        self.assertEqual(str(mirror_dir), report["sources"]["vuln_list_mirror"])
        self.assertEqual(str(exploit_db), report["sources"]["exploit_db"])
        self.assertEqual(core_stub, report["core"])
        self.assertEqual(1, len(report["trivy_vuln_list"]))
        self.assertEqual("ubuntu", report["trivy_vuln_list"][0]["source"])
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
        self.assertEqual(["kev"], report["impact"]["evidence"]["signals"])
