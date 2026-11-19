from unittest.mock import patch

from scripts import intel


def test_candidates_preserves_routes_and_fixed_window():
    windows = []

    def search(db_path, **kwargs):
        windows.append((kwargs["since"], kwargs["until"]))
        return {"items": [{"vuln_id": "CVE-2026-1", "signal_id": len(windows)}],
                "feed_status": {}, "unindexed": 0}

    with patch.object(intel, "search", side_effect=search), patch.object(
        intel.THEMES.__class__, "read_text", return_value='{"Java":{"terms":["Java"]}}'
    ):
        result = intel.candidates(None, until="2026-11-19T15:28:00+09:00", limit=1)
    assert len(set(windows)) == 1
    assert len(result["items"]) == 1
    assert [hit["route"] for hit in result["items"][0]["hits"]] == [
        "overall", "attention", "theme:Java"]
    assert [hit["signal_id"] for hit in result["items"][0]["hits"]] == [1, 2, 3]
    assert all(route["limit_reached"] for route in result["searches"])
