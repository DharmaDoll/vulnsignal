from db.migrate import migrate
from scripts.intel import refresh, search
from sync.common import append_signal, connect


def test_mart_dates_provenance_and_incremental_refresh(tmp_path):
    db = tmp_path / "core.db"
    migrate(db)
    vuln = "CVE-2020-12345"
    observed = "2026-11-19T00:00:00Z"
    with connect(db) as conn:
        append_signal(conn, vuln, "enrichment", "CVE Program", 9.5,
                      {"title":"JavaScript issue", "published_at":"2020-01-01", "cvss_score":9.5}, observed)
        append_signal(conn, vuln, "enrichment", "Trivy JSON", 10, {"title":"Java"}, observed)
        append_signal(conn, vuln, "enrichment", "CISA Vulnrichment", 10,
                      {"title":"CISA ADP Vulnrichment","source_fields_version":1}, observed)
    refresh(db)
    assert search(db, kind="critical", since="2026-11-18")["items"] == []
    assert search(db, terms=["Java"])["items"] == []
    assert search(db, vuln_id=vuln)["items"][0]["title"] == "JavaScript issue"
    with connect(db) as conn:
        append_signal(conn, vuln, "kev", "CISA KEV", 1, {"product":"OpenJDK","date_added":"2026-11-18"}, observed)
    refresh(db)
    steady = refresh(db)
    assert steady["previous_signal_id"] == steady["last_signal_id"]
    rows = search(db, terms=["OpenJDK"], product_only=True, until="2026-11-20")["items"]
    assert rows[0]["kind"] == "kev"
    assert rows[0]["source_date"].startswith("2026-11-18")
    assert rows[0]["observed_at"].startswith("2026-11-19")
    assert not search(db, terms=["OpenJDK"], until="2026-11-18")["items"]


def test_cvss_changes_and_epss_on_the_same_search(tmp_path):
    db = tmp_path / "core.db"
    migrate(db)
    vuln = "CVE-2025-1001"

    def observe(conn, score, day, provider="CVE Program", version="3.1"):
        value = {"cvss_score":score, "cvss_vector":f"CVSS:{version}/AV:N", "published_at":"2025-01-01"}
        return append_signal(conn,vuln,"enrichment",provider,score,value,f"2026-01-{day:02}T01:00:00Z")

    with connect(db) as conn:
        observe(conn, 5, 1)
        observe(conn, 9, 3)
        assert not observe(conn, 9, 4)
        assert observe(conn, 5, 5)
        observe(conn, 8, 6, version="4.0")
        observe(conn, 7.5, 2, provider="GitHub Advisory Database")
        conn.execute("INSERT INTO epss_current VALUES(?,?,?,?,?)",
                     (vuln,.8,.995,"2026-01-05","2026-01-06T06:00:00Z"))
    refresh(db)
    with connect(db) as conn:
        observe(conn, 6, 2)  # arrives late, before the previously indexed 9
    refresh(db)
    refresh(db)
    rises = search(db,kind="cvss_increase",min_percentile=.99,sort="epss",until="2026-02-01")["items"]
    assert len(rises) == 1
    assert rises[0]["cvss_change"]["previous_score"] == 6
    assert rises[0]["cvss_change"]["new_score"] == 9
    assert rises[0]["cvss_change"]["delta"] == 3
    assert rises[0]["cvss"]["score"] == 7.5  # highest-trust current source
    assert rises[0]["epss"]["score_date"] == "2026-01-05"
    falls = search(db,vuln_id=vuln,kind="cvss_decrease")["items"]
    assert len(falls) == 1 and falls[0]["cvss_change"]["delta"] == -4
    assert len(search(db,vuln_id=vuln,kind="cvss_increase")["items"]) == 2
    before = search(db,kind="cvss_increase",since="2026-01-02",until="2026-01-04")["items"]
    assert before and before[0]["epss"] is None
    assert not search(db,kind="cvss_increase",min_epss=0,until="2026-01-04")["items"]


def test_epss_filters_before_limit_and_nulls_last(tmp_path):
    db = tmp_path / "core.db"
    migrate(db)
    with connect(db) as conn:
        for i, value in enumerate([None,.1,.8]):
            vuln = f"CVE-2025-100{i}"
            append_signal(conn,vuln,"exploit","go-exploitdb",1,{"url":"https://example.invalid/reference"},
                          "2026-01-01T00:00:00Z")
            if value is not None:
                conn.execute("INSERT INTO epss_current VALUES(?,?,?,?,?)",
                             (vuln,value,value,"2026-01-01","2026-01-01T12:00:00Z"))
    refresh(db)
    rows = search(db,kind="exploit_reference",sort="epss")["items"]
    assert [row["epss"]["score"] if row["epss"] else None for row in rows] == [.8,.1,None]
    assert search(db,min_epss=.5,min_percentile=.8,limit=1)["items"][0]["vuln_id"] == "CVE-2025-1002"


def test_ghsa_vector_aliases_and_reversion(tmp_path):
    db = tmp_path / "core.db"
    migrate(db)
    cve = "CVE-2026-0001"
    advisory = "GHSA-example"
    low = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    high = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    with connect(db) as conn:
        for day, vector in enumerate([low, high, low], 1):
            value = {"ghsa_id":advisory, "aliases":[cve], "cvss_vector":vector}
            for identifier in (advisory,cve):
                assert append_signal(conn,identifier,"enrichment","GitHub Advisory Database",None,
                                     value,f"2026-01-0{day}T00:00:00Z")
    refresh(db)
    changes = search(db,vuln_id=advisory,kind="cvss_increase")["items"]
    assert len(changes) == 1 and changes[0]["vuln_id"] == cve
    assert changes[0]["cvss_change"]["new_score"] == 9.8
    assert changes[0]["cvss"]["score_origin"] == "vector"
    assert changes[0]["cvss"]["score"] == changes[0]["cvss_change"]["previous_score"]
    assert len(search(db,vuln_id=cve,kind="cvss_decrease")["items"]) == 1


def test_refresh_rechecks_old_hot_terms_dates_and_urls_atomically(tmp_path):
    from scripts.intel import instant

    path = tmp_path / "core.db"
    migrate(path)
    vuln = "CVE-2026-1234"
    good = "https://thehackernews.com/java"
    bad = "https://thehackernews.com/checklist"
    observed = "2026-11-18T00:00:00Z"
    old_title = "AI pentesting checklist"
    with connect(path) as conn:
        append_signal(conn, vuln, "hot", "Web Hot Intel", 0.9, {
            "headline": old_title, "urls": [bad, good],
            "evidence_details": [{"url": bad, "title": old_title},
                                 {"url": good, "title": f"Java4Shell {vuln}"}],
            "discovery_hits": [{"url": bad, "cve_ids": [vuln]},
                               {"url": good, "published_at": "Sun, 15 Nov 2026 12:00:00 GMT"}],
        }, observed)
        sid = conn.execute("SELECT id FROM signals").fetchone()[0]
        conn.execute("INSERT INTO intel_state VALUES(1,?,1)", (sid,))
        conn.execute("INSERT INTO intel_evidence VALUES(?,?,?,?,?)",
                     (sid, vuln, "Web Hot Intel", old_title, instant(observed)))
        conn.execute("INSERT INTO intel_terms(rowid,product,mention) VALUES(?,'',?)", (sid, old_title))
        for url in (bad, good):
            conn.execute("INSERT INTO intel_event VALUES(?,'attention',?,?,NULL,?)",
                         (vuln, url, sid, instant(observed)))
    for _ in range(2):
        refresh(path)
        args = {"kind": "attention", "until": "2026-11-20"}
        assert not search(path, terms=["pentesting"], **args)["items"]
        item, = search(path, terms=["Java4Shell"], **args)["items"]
        assert item["references"] == [good]
        assert item["source_date"] == instant("2026-11-15T12:00:00Z")
        assert item["match"]["text"] == f"Java4Shell {vuln}"
        assert not search(path, since="2026-11-17", **args)["items"]
    with connect(path) as conn:
        assert conn.execute("SELECT count(*) FROM signals").fetchone()[0] == 1
