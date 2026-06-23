from __future__ import annotations

from unittest import TestCase
from unittest.mock import patch

from app.routing import plan_request
from scripts import run_route


class RoutingTests(TestCase):
    def test_single_cve_deep_dive_routes_to_sub_agent(self) -> None:
        plan = plan_request("Deep dive CVE-2026-31431")

        self.assertEqual("deep_dive", plan.mode)
        self.assertEqual("main", plan.primary_agent)
        self.assertGreaterEqual(len(plan.sub_agents), 1)
        self.assertIn("CVE-2026-31431", plan.summary)
        self.assertIn("docs/DEEP_DIVE.md", plan.source_docs)

    def test_watchlist_mentions_route_to_analysis_mode(self) -> None:
        plan = plan_request("ここ三日間の注目の脆弱性を30件")

        self.assertEqual("watchlist", plan.mode)
        self.assertEqual("main", plan.primary_agent)
        self.assertGreaterEqual(len(plan.sub_agents), 1)
        self.assertTrue(any("watchlist" in step.task.lower() for step in plan.sub_agents))

    @patch("scripts.run_route._route_plan", return_value={"mode": "deep_dive", "primary_agent": "main", "summary": "s"})
    @patch("scripts.run_route._deep_dive", return_value={"vuln_id": "CVE-2026-31431"})
    def test_execute_deep_dive_routes_to_worker(self, mock_deep_dive, mock_route_plan) -> None:
        payload = run_route.execute("CVE-2026-31431 deep dive")

        self.assertEqual("deep_dive", payload["route"]["mode"])
        self.assertEqual({"vuln_id": "CVE-2026-31431"}, payload["result"])
        self.assertEqual("deep_dive", payload["artifact"]["kind"])
        self.assertIn("generated_at", payload)
        mock_route_plan.assert_called_once()
        mock_deep_dive.assert_called_once()
