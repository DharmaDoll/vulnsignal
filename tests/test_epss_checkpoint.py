import gzip

from db.migrate import migrate
from sync import fetch_epss
from sync.common import connect


def test_checkpoint_requires_complete_success_and_matching_content(tmp_path, monkeypatch):
    db = tmp_path / "core.db"
    migrate(db)
    monkeypatch.setattr(fetch_epss, "connect", lambda: connect(db))
    monkeypatch.setattr(fetch_epss, "CACHE_DIR", tmp_path)
    day = "2026-03-04"
    cached = fetch_epss.cache_path(day)
    cached.write_bytes(gzip.compress(b"cve,epss,percentile\nCVE-2026-1000,0.1,0.9\n"))
    fetch_epss.sync(limit=1, score_date=day, cache_only=True)
    with connect(db) as conn:
        assert conn.execute("SELECT count(*) FROM epss_batch").fetchone()[0] == 0
    fetch_epss.sync(score_date=day, cache_only=True)
    monkeypatch.setattr(fetch_epss, "fetch_bytes", lambda *a, **kw: (_ for _ in ()).throw(AssertionError()))
    assert fetch_epss.sync(score_date=day).rows_fetched == 0
    cached.write_bytes(gzip.compress(b"cve,epss,percentile\nCVE-2026-1000,0.4,0.9\n"))
    assert fetch_epss.sync(score_date=day, cache_only=True).rows_written == 1


def test_cli_measurement_attaches_to_the_same_fetch_row(tmp_path, monkeypatch):
    from sync import common
    path = tmp_path / "metrics.db"
    monkeypatch.setattr(common, "DB_PATH", path)
    monkeypatch.setattr(common, "connect", lambda: connect(path))
    monkeypatch.setattr(common, "_download_bytes", lambda *args: b"example")

    def run():
        assert common.fetch_bytes("https://example.invalid") == b"example"
        with connect(path) as conn:
            common.log_fetch(conn, "kev", "ok", 1)
        return common.FetchResult(5, 1)

    common.run_measured("kev", run)
    with connect(path) as conn:
        row = conn.execute("SELECT f.rows_affected,m.rows_read,m.http_body_bytes FROM fetch_log f "
                           "JOIN feed_metrics m ON m.fetch_id=f.id").fetchone()
        assert tuple(row) == (1, 5, 7)
