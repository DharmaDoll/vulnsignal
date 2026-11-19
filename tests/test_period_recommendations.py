import gzip
import json
from datetime import date, datetime, timezone

from db.migrate import migrate
from scripts import period_recommendations as reports
from sync.common import append_signal, connect


def test_period_cutoff_and_replay(tmp_path):
    path = tmp_path / "db"
    migrate(path)
    vuln = "CVE-2020-1234"
    with connect(path) as db:
        for when, kind, provider, value in (
            ("2026-01-01", "enrichment", "CVE Program", {"title": "JavaScript issue", "summary": "Affects the Postgres adapter"}),
            ("2026-03-31", "package_advisory", "GitHub Advisory Database", {"package_name": "react"}),
            ("2026-04-03", "kev", "CISA KEV", {"date_added": "2026-04-02"}),
            ("2026-04-04", "hot", "Web Hot Intel", {"urls": ["https://example.org/news/CVE-2020-1234"]}),
            ("2026-04-04", "package_advisory", "Trivy JSON", {"package_name": "Java"}),
            ("2026-04-05", "enrichment", "CVE Program", {"title": "Future evidence"}),
        ):
            append_signal(db, vuln, kind, provider, None, value, when + "T00:00:00Z")
    artifact = reports.create_artifact(path, "quarter", date(2026, 4, 4), "UTC",
                                       datetime(2026, 4, 5, tzinfo=timezone.utc))
    report = reports.render(artifact)
    assert report["overall"] == [vuln]
    assert report["themes"] == {"React": [vuln], "Java": [], "PostgreSQL": [vuln]}
    assert report["items"][0]["title"] == "JavaScript issue"
    assert len(report["items"][0]["changes"]) == 2
    assert not report["previous_period"]["comparable"]
    assert report["previous_period"]["overall"] == []
    saved = reports.save_artifact(artifact, tmp_path)
    with gzip.open(saved) as f:
        replay = json.load(f)
    assert reports.render(replay) == report
    replay["themes"] = {"JS": {"terms": ["JavaScript"]}}
    assert reports.render(replay)["themes"] == {"JS": [vuln]}
    assert replay["report"]["overall"] == report["overall"]


def test_repeated_hot_urls_do_not_resurface(tmp_path):
    path = tmp_path / "db"
    migrate(path)
    with connect(path) as db:
        for day in (1, 2):
            append_signal(db, "CVE-2010-1234", "hot", "Web Hot Intel", None,
                          {"urls": ["https://example.org/CVE-2010-1234"], "search_budget": day}, f"2026-01-0{day}T00:00:00Z")
    artifact = reports.create_artifact(path, "day", date(2026, 1, 2), "UTC", datetime(2026, 2, 1, tzinfo=timezone.utc))
    assert reports.render(artifact)["overall"] == []


def test_calendar_boundaries():
    from zoneinfo import ZoneInfo
    zone = ZoneInfo("America/New_York")
    start, end = reports.bounds("week", date(2026, 3, 8), zone)
    assert start.date() == date(2026, 3, 2)
    assert end.date() == date(2026, 3, 9)
    assert end.timestamp() - start.timestamp() == 167 * 3600
    start, end = reports.bounds("quarter", date(2026, 12, 31), zone)
    assert start.date() == date(2026, 10, 1)
    assert end.date() == date(2027, 1, 1)


def test_blind_evaluation_includes_methods_and_independent_misses():
    from scripts.evaluate_recommendations import prepare, score
    artifact = {"report": {"overall": ["A"]}, "period_start": "start", "snapshot": {"cutoff": "end"}}
    ballot, methods = prepare(artifact, ["B"], ["A"], "stable")
    assert "methods" not in ballot
    for row in ballot["reviews"]:
        row["worth_reading"] = row["vuln_id"] == "A"
    ballot["independent_watchlist"] = ["A", "C"]
    results = score(ballot, methods)
    assert results["rules"]["precision"] == 1
    assert results["rules"]["missed"] == ["C"]
    assert results["fixed_prompt"]["missed"] == ["A", "C"]


def test_older_kev_entry_is_labelled_as_backfill_and_aliases_share_one_item(tmp_path):
    db_path = tmp_path / "core.db"
    migrate(db_path)
    vuln = "CVE-2020-1234"
    with connect(db_path) as db:
        append_signal(db, vuln, "kev", "CISA KEV", 1, {"date_added": "2025-01-01"}, "2026-04-04T00:00:00Z")
        value = {"ghsa_id": "GHSA-example", "aliases": [vuln], "fixed_version": "1.1", "package_name": "react"}
        for identifier in (vuln, "GHSA-example"):
            append_signal(db, identifier, "package_advisory", "GitHub Advisory Database", None,
                          value, "2026-04-04T01:00:00Z")
    report = reports.render(reports.create_artifact(db_path, "week", date(2026, 4, 4), "UTC",
                                                     datetime(2026, 4, 5, tzinfo=timezone.utc)))
    assert report["overall"] == [vuln]
    changes = report["items"][0]["changes"]
    assert len(changes) == 2
    assert changes[0]["reason"] == "過去のKEV掲載を新規収録"
