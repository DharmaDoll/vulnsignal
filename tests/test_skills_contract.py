from __future__ import annotations

from unittest import TestCase

from app import skills


class SkillsContractTests(TestCase):
    def test_build_json_envelope_is_versioned(self) -> None:
        payload = skills.build_json_envelope("hot", [{"vuln_id": "CVE-2026-31431"}], generated_at="2026-06-26T00:00:00Z")

        self.assertEqual(1, payload["schema_version"])
        self.assertEqual("hot", payload["kind"])
        self.assertEqual([{"vuln_id": "CVE-2026-31431"}], payload["result"])
        self.assertEqual("2026-06-26T00:00:00Z", payload["generated_at"])
