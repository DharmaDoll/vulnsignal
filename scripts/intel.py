"""Search the local vulnerability intelligence mart. Outputs JSON to stdout."""
import argparse
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

from db.migrate import migrate
from scripts.period_recommendations import FIELDS, PROVIDERS, THEMES, validate_themes
from sync.feed_quality import MAX_STALENESS_HOURS
from sync.common import DB_PATH, connect
from sync.hot_intel import reviewed_hot_value
from sync.cvss import rating

GENERIC = {"cisa adp vulnrichment", "cve program container", "cisa adp container"}
KINDS = ("kev", "attention", "exploit_reference", "fix", "critical", "advisory", "cvss_increase", "cvss_decrease")


def instant(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")


def events(kind, value, provider):
    if kind == "kev":
        yield "kev", "KEV", value.get("date_added")
    elif kind == "hot":
        dates = {detail["url"]: detail.get("published_at") for detail in value.get("evidence_details") or []
                 if detail.get("url")}
        for url in value.get("urls") or []:
            if isinstance(url, str) and url:
                yield "attention", url, dates.get(url)
    elif kind == "exploit" and value.get("url"):
        yield "exploit_reference", value["url"], None
    elif kind == "package_advisory" and value.get("package_name"):
        fixed = value.get("fixed_version")
        if fixed:
            yield "fix", json.dumps([value.get("ecosystem"), value["package_name"], fixed]), None
    elif kind == "enrichment":
        score = value.get("cvss_score")
        label = "critical" if isinstance(score, (int, float)) and score >= 9 else "advisory"
        yield label, json.dumps([provider, value.get("ghsa_id"), score]), value.get("published_at")


def project(conn, row):
    provider = row["provider"]
    if provider not in PROVIDERS:
        return
    value = json.loads(row["value_json"] or "{}")
    if provider == "CISA Vulnrichment" and not value.get("source_fields_version"):
        return
    vuln_id = row["vuln_id"]
    if row["signal_type"] == "hot":
        value = reviewed_hot_value(vuln_id, value)
        if not value:
            return
    if vuln_id.startswith("GHSA-"):
        aliases = {a for a in value.get("aliases") or [] if isinstance(a, str) and a.startswith("CVE-")}
        if len(aliases) == 1:
            vuln_id = aliases.pop()
    observed = instant(row["observed_at"])
    product = " ".join(str(value[k]) for k in ("vendor_project", "product", "package_name") if value.get(k))
    title = next((v.strip() for v in (value.get("title"), value.get("headline"))
                  if isinstance(v, str) and v.strip() and v.strip().casefold() not in GENERIC), None)
    summary = value.get("summary") or ""
    conn.execute("INSERT INTO intel_evidence VALUES (?,?,?,?,?)",
                 (row["id"], vuln_id, provider, title, observed))
    if product or title or summary:
        conn.execute("INSERT INTO intel_terms(rowid,product,mention) VALUES (?,?,?)",
                     (row["id"], product, " ".join(filter(None, [title, summary]))))
    for kind, key, source in events(row["signal_type"], value, provider):
        try:
            source_time = instant(source) if source else None
        except (ValueError, TypeError, AttributeError):
            source_time = None
        conn.execute("""
            INSERT INTO intel_event VALUES (?,?,?,?,?,?)
            ON CONFLICT(vuln_id,kind,identity) DO UPDATE SET
                source_date=excluded.source_date,effective_at=excluded.effective_at,signal_id=excluded.signal_id
            WHERE intel_event.source_date IS NULL AND excluded.source_date IS NOT NULL
        """, (vuln_id, kind, key, row["id"], source_time, source_time or observed))


def index_ratings(conn, start, end):
    """Index an evidence ID interval, including evidence projected before migration 011."""
    rows = conn.execute("""
        SELECT d.signal_id,d.vuln_id,d.provider,d.observed_at,s.value_json
        FROM intel_evidence d JOIN signals s ON s.id=d.signal_id
        WHERE d.signal_id>? AND d.signal_id<=? AND s.signal_type='enrichment'
        ORDER BY d.signal_id
    """, (start, end))
    for row in rows:
        measurement = rating(json.loads(row["value_json"]))
        if measurement is None:
            continue
        score, advisory, version = measurement
        scope = (row["vuln_id"], row["provider"], advisory, version)
        position = (row["observed_at"], row["signal_id"])
        inserted = conn.execute("""INSERT OR IGNORE INTO intel_cvss(vuln_id,provider,advisory,version,observed_at,signal_id,score)
                        VALUES(?,?,?,?,?,?,?)""", (*scope, *position, score))
        if not inserted.rowcount:
            continue
        series = "FROM intel_cvss WHERE vuln_id=? AND provider=? AND advisory=? AND version=?"
        prev = conn.execute("SELECT * " + series + " AND (observed_at,signal_id)<(?,?) "
                            "ORDER BY observed_at DESC,signal_id DESC LIMIT 1", (*scope,*position)).fetchone()
        # A late-arriving observation can also change its successor's predecessor.
        following = conn.execute("SELECT * " + series + " AND (observed_at,signal_id)>(?,?) "
                                 "ORDER BY observed_at,signal_id LIMIT 1", (*scope,*position)).fetchone()
        write_revision(conn, prev, row, score)
        if following:
            write_revision(conn, {"signal_id": row["signal_id"], "score": score}, following, following["score"])
    conn.execute("INSERT OR REPLACE INTO intel_cvss_state VALUES(1,?)", (end,))


def write_revision(conn, previous, current, score):
    # These are derived events. The underlying observations remain append-only.
    key = str(current["signal_id"])
    conn.execute("DELETE FROM intel_event WHERE vuln_id=? AND identity=? AND kind IN "
                 "('cvss_increase','cvss_decrease')", (current["vuln_id"], key))
    if previous is not None and previous["score"] != score:
        kind = "cvss_increase" if score > previous["score"] else "cvss_decrease"
        conn.execute("INSERT INTO intel_event VALUES(?,?,?,?,NULL,?)",
                     (current["vuln_id"], kind, key, current["signal_id"], current["observed_at"]))


def reindex_hot(conn, end):
    """Replace only v1 hot projections, preserving original FTS tokens for deletion."""
    rows = conn.execute("""
        SELECT s.*,d.title AS indexed_title FROM intel_evidence d JOIN signals s ON s.id=d.signal_id
        WHERE d.provider='Web Hot Intel' AND s.signal_type='hot' AND d.signal_id<=? ORDER BY s.id
    """, (end,)).fetchall()
    conn.execute("DELETE FROM intel_event WHERE kind='attention' AND signal_id IN "
                 "(SELECT signal_id FROM intel_evidence WHERE provider='Web Hot Intel' AND signal_id<=?)", (end,))
    for row in rows:
        value = json.loads(row["value_json"])
        product = " ".join(str(value[k]) for k in ("vendor_project", "product", "package_name") if value.get(k))
        mention = " ".join(filter(None, (row["indexed_title"], value.get("summary"))))
        if product or mention:
            conn.execute("INSERT INTO intel_terms(intel_terms,rowid,product,mention) VALUES('delete',?,?,?)",
                         (row["id"], product, mention))
        conn.execute("DELETE FROM intel_evidence WHERE signal_id=?", (row["id"],))
        project(conn, row)


def refresh(db_path):
    migrate(db_path)
    with closing(connect(db_path)) as conn:
        end = conn.execute("SELECT coalesce(max(id),0) FROM signals").fetchone()[0]
        initial = None
        while True:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute("SELECT last_signal_id,hot_rule_version FROM intel_state").fetchone()
            start = cursor[0] if cursor else 0
            if cursor and cursor["hot_rule_version"] < 2:
                reindex_hot(conn, start)
            if initial is None:
                initial = start
            last = start
            for row in conn.execute("SELECT * FROM signals WHERE id>? AND id<=? ORDER BY id LIMIT 2000",
                                    (start, end)):
                project(conn, row)
                last = row["id"]
            conn.execute("INSERT OR REPLACE INTO intel_state(singleton,last_signal_id,hot_rule_version) VALUES (1,?,2)", (last,))
            cvss_state = conn.execute("SELECT last_signal_id FROM intel_cvss_state").fetchone()
            cvss_start = cvss_state[0] if cvss_state else 0
            cvss_end = min(last, cvss_start + 5000)
            if cvss_end > cvss_start:
                index_ratings(conn, cvss_start, cvss_end)
            conn.commit()
            if last >= end and cvss_end >= end:
                return {"previous_signal_id": initial, "last_signal_id": last}


def phrase(term):
    return '"' + term.replace('"', '""') + '"'


def search(db_path, *, terms=(), exclude=(), vuln_id=None, since=None, until=None,
           kind=None, limit=10, product_only=False, clock="effective", min_epss=None, min_percentile=None, sort="priority"):
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if any(x is not None and not 0 <= x <= 1 for x in (min_epss, min_percentile)):
        raise ValueError("EPSS and percentile thresholds must be between 0 and 1")
    if sort not in ("priority", "epss"):
        raise ValueError("sort must be priority or epss")
    end = instant(until or datetime.now(timezone.utc).isoformat())
    start = instant(since) if since else None
    if start and start >= end:
        raise ValueError("since must precede until")
    filters = ["e.effective_at < :end", "s.observed_at < :end"]
    time_column = {"effective": "e.effective_at", "observed": "s.observed_at", "source": "e.source_date"}[clock]
    if clock == "source":
        filters.append("e.source_date IS NOT NULL")
    params = {"end": end, "limit": limit}
    match = ""
    if terms:
        expression = "(" + " OR ".join(map(phrase, terms)) + ")"
        if exclude:
            expression += " NOT (" + " OR ".join(map(phrase, exclude)) + ")"
        params["product_match"] = "product : (" + expression + ")"
        params["match"] = ("product : " if product_only else "") + expression
        match = """JOIN (SELECT DISTINCT d.vuln_id FROM intel_terms
                    JOIN intel_evidence d ON d.signal_id=intel_terms.rowid
                    WHERE intel_terms MATCH :match AND d.observed_at < :end) m ON m.vuln_id=e.vuln_id"""
    if start:
        filters.append(f"{time_column} >= :start")
        if clock == "effective":
            filters.append("(e.source_date IS NOT NULL OR e.kind IN ('kev','exploit_reference','attention','cvss_increase','cvss_decrease'))")
        params["start"] = start
    if vuln_id:
        filters.append("(e.vuln_id IN (:vuln,:alias) OR e.vuln_id IN (SELECT d.vuln_id FROM intel_evidence d "
                       "JOIN signals raw ON d.signal_id=raw.id WHERE raw.vuln_id IN (:vuln,:alias) AND d.observed_at<:end))")
        params["vuln"] = vuln_id.upper()
        params["alias"] = "GHSA-" + vuln_id[5:].lower() if vuln_id.upper().startswith("GHSA-") else params["vuln"]
    if kind:
        filters.append("e.kind=:kind")
        params["kind"] = kind
    for column, threshold in (("epss", min_epss), ("percentile", min_percentile)):
        if threshold is not None:
            filters.append(f"p.{column} >= :min_{column}")
            params[f"min_{column}"] = threshold
    selection = "" if vuln_id else "WHERE n=1"
    ordering = "effective_at DESC,signal_id DESC,identity" if vuln_id else "priority DESC,effective_at DESC,vuln_id"
    if sort == "epss":
        ordering = "epss DESC NULLS LAST," + ordering
    sql = f"""WITH eligible AS (
        SELECT e.*,s.observed_at,s.provider,p.epss,p.percentile,p.score_date,p.updated_at AS epss_updated_at,
               CASE e.kind WHEN 'kev' THEN 4 WHEN 'attention' THEN 3 WHEN 'exploit_reference' THEN 2
                           WHEN 'cvss_increase' THEN 2 WHEN 'critical' THEN 1 ELSE 0 END AS priority
        FROM intel_event e JOIN intel_evidence s USING(signal_id) {match}
        LEFT JOIN epss_current p ON p.vuln_id=e.vuln_id AND julianday(p.updated_at)<julianday(:end)
                                AND julianday(p.score_date)<julianday(:end)
        WHERE {' AND '.join(filters)}
    ), ordered AS (
        SELECT *,row_number() OVER (PARTITION BY vuln_id ORDER BY priority DESC,effective_at DESC,signal_id DESC,identity) AS n
        FROM eligible
    ) SELECT * FROM ordered {selection} ORDER BY {ordering} LIMIT :limit"""
    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN")
        items = []
        for row in conn.execute(sql, params):
            v = row["vuln_id"]
            title = conn.execute("""SELECT title FROM intel_evidence WHERE vuln_id=? AND observed_at<?
                                    AND title IS NOT NULL ORDER BY
                                    CASE provider WHEN 'CVE Program' THEN 0 WHEN 'GitHub Advisory Database' THEN 1 ELSE 2 END,
                                    observed_at DESC,signal_id DESC LIMIT 1""", (v, end)).fetchone()
            raw = json.loads(conn.execute("SELECT value_json FROM signals WHERE id=?",(row["signal_id"],)).fetchone()[0])
            references = raw.get("references") or ([raw["url"]] if raw.get("url") else [])
            if row["kind"] == "attention":
                references = [row["identity"]]
            if row["kind"] == "kev":
                references = ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"]
            item = {key: row[key] for key in ("vuln_id","kind","provider","signal_id","source_date","observed_at","effective_at")}
            item.update(title=title[0] if title else v, references=references[:5],
                        time_basis="source" if row["source_date"] else "first_local_observation")
            item["epss"] = None if row["epss"] is None else {
                "score": row["epss"], "percentile": row["percentile"], "score_date": row["score_date"],
                "observed_at": row["epss_updated_at"]}
            current = conn.execute("""
                SELECT c.score,c.provider,c.version,c.advisory,c.observed_at,c.signal_id,
                       CASE WHEN json_type(s.value_json,'$.cvss_score') IN ('integer','real')
                            THEN 'reported' ELSE 'vector' END AS score_origin
                FROM intel_cvss c JOIN signals s ON s.id=c.signal_id
                WHERE c.vuln_id=? AND c.observed_at<? ORDER BY CASE c.provider
                    WHEN 'GitHub Advisory Database' THEN 0 WHEN 'CISA Vulnrichment' THEN 1 ELSE 2 END,
                    c.observed_at DESC,c.signal_id DESC LIMIT 1
            """, (v,end)).fetchone()
            item["cvss"] = dict(current) if current else None
            if row["kind"] in ("cvss_increase", "cvss_decrease"):
                revision = conn.execute("""
                    SELECT a.score AS previous_score,a.signal_id AS previous_signal_id,b.score AS new_score,
                           b.version,b.advisory,round(b.score-a.score,1) AS delta
                    FROM intel_cvss b JOIN intel_cvss a USING(vuln_id,provider,version,advisory)
                    WHERE b.signal_id=? AND (a.observed_at,a.signal_id)<(b.observed_at,b.signal_id)
                    ORDER BY a.observed_at DESC,a.signal_id DESC LIMIT 1
                """, (row["signal_id"],)).fetchone()
                item["cvss_change"] = dict(revision)
                item["time_basis"] = "local_score_change"
            if terms:
                hit = conn.execute("""SELECT d.signal_id,d.title AS indexed_title,raw.value_json,
                      EXISTS(SELECT 1 FROM intel_terms WHERE rowid=d.signal_id AND intel_terms MATCH :product_match) AS is_product
                      FROM intel_terms
                      JOIN intel_evidence d ON intel_terms.rowid=d.signal_id JOIN signals raw ON raw.id=d.signal_id
                      WHERE intel_terms MATCH :match AND d.vuln_id=:id AND d.observed_at<:end
                      ORDER BY is_product DESC,d.observed_at DESC,d.signal_id DESC LIMIT 1""", {**params,"id":v}).fetchone()
                evidence = json.loads(hit["value_json"])
                item["match"] = {"basis": "product_or_package" if hit["is_product"] else "text_mention",
                                 "signal_id":hit["signal_id"], "product":evidence.get("product") or evidence.get("package_name"),
                                 "text":(hit["indexed_title"] or evidence.get("summary") or "")[:240]}
            items.append(item)
        feeds = {}
        for feed in (*PROVIDERS.values(), "epss"):
            # The most recent online success is relevant even after a failed or cached run.
            last = conn.execute("""SELECT attempted_at FROM fetch_log WHERE feed=? AND status='ok'
                                   AND cache_used=0 AND julianday(attempted_at)<julianday(?)
                                   ORDER BY attempted_at DESC,id DESC LIMIT 1""", (feed, end)).fetchone()
            observed = instant(last[0]) if last else None
            stale = not observed or datetime.fromisoformat(end) - datetime.fromisoformat(observed) > timedelta(
                hours=MAX_STALENESS_HOURS[feed])
            feeds[feed] = {"last_online_ingest": observed, "stale": stale}
        state = conn.execute("SELECT last_signal_id FROM intel_state").fetchone()
        head = conn.execute("SELECT max(id) FROM signals").fetchone()[0] or 0
    return {"since":start,"until":end,"clock":clock,"feed_status":feeds,"indexed_through":state[0] if state else 0,
            "unindexed":head-(state[0] if state else 0),"items":items}


def candidates(db_path, *, since=None, until=None, limit=10):
    """Collect bounded search routes using one decision window."""
    end = instant(until or datetime.now(timezone.utc).isoformat())
    start = instant(since) if since else (
        datetime.fromisoformat(end) - timedelta(days=7)).isoformat()
    themes = json.loads(THEMES.read_text())
    validate_themes(themes)
    routes = [("overall", {}), ("attention", {"kind": "attention"})]
    routes.extend(
        ("theme:" + name, {"terms": config["terms"], "exclude": config.get("exclude", [])})
        for name, config in themes.items()
    )
    merged = {}
    searches = []
    for name, options in routes:
        result = search(db_path, since=start, until=end, limit=limit, **options)
        searches.append({"route": name, "count": len(result["items"]),
                         "limit_reached": len(result["items"]) == limit})
        for rank, item in enumerate(result["items"], 1):
            entry = merged.setdefault(item["vuln_id"], {"vuln_id": item["vuln_id"], "hits": []})
            entry["hits"].append({"route": name, "rank": rank, **item})
    return {"since": start, "until": end, "per_search_limit": limit,
            "feed_status": result["feed_status"], "unindexed": result["unindexed"],
            "searches": searches, "items": list(merged.values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db-path", type=Path, default=DB_PATH)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("refresh")
    collect = sub.add_parser("candidates")
    collect.add_argument("--since")
    collect.add_argument("--until")
    collect.add_argument("--limit", type=int, default=10, help="Maximum items per search route.")
    evidence = sub.add_parser("evidence")
    evidence.add_argument("signal_id", type=int)
    query = sub.add_parser("search")
    query.add_argument("--id")
    group = query.add_mutually_exclusive_group()
    group.add_argument("--term")
    group.add_argument("--theme")
    query.add_argument("--product-only", action="store_true")
    query.add_argument("--clock", choices=["source", "observed", "effective"], default="effective")
    query.add_argument("--since")
    query.add_argument("--until")
    query.add_argument("--kind", choices=KINDS)
    query.add_argument("--min-epss", type=float)
    query.add_argument("--min-percentile", type=float)
    query.add_argument("--sort", choices=("priority","epss"), default="priority")
    query.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()
    if args.command == "refresh":
        result = refresh(args.db_path)
    elif args.command == "candidates":
        migrate(args.db_path)
        result = candidates(args.db_path, since=args.since, until=args.until, limit=args.limit)
    elif args.command == "evidence":
        migrate(args.db_path)
        with closing(connect(args.db_path)) as conn:
            row = conn.execute("""SELECT d.*,s.signal_type,s.value_json FROM intel_evidence d
                                  JOIN signals s ON d.signal_id=s.id WHERE d.signal_id=?""",
                               (args.signal_id,)).fetchone()
        if row is None:
            parser.error("unknown indexed signal")
        result = dict(row)
        value = json.loads(result.pop("value_json") or "{}")
        if result["signal_type"] == "hot":
            value = reviewed_hot_value(result["vuln_id"], value) or {}
        result["evidence"] = {k: value[k] for k in (*FIELDS, "cvss_vector") if value.get(k) is not None}
    else:
        migrate(args.db_path)
        terms = [args.term] if args.term else []
        exclude = []
        if args.theme:
            themes = json.loads(THEMES.read_text())
            validate_themes(themes)
            if args.theme not in themes:
                parser.error("unknown theme: " + args.theme)
            terms = themes[args.theme]["terms"]
            exclude = themes[args.theme].get("exclude", [])
        if args.since is None and not args.id:
            cutoff = datetime.fromisoformat(instant(args.until)) if args.until else datetime.now(timezone.utc)
            args.since = (cutoff - timedelta(days=7)).isoformat()
        result = search(args.db_path,terms=terms,exclude=exclude,vuln_id=args.id,since=args.since,until=args.until,
                        limit=args.limit,kind=args.kind,product_only=args.product_only,clock=args.clock,
                        min_epss=args.min_epss,min_percentile=args.min_percentile,sort=args.sort)
    print(json.dumps(result,ensure_ascii=False))


if __name__ == "__main__":
    main()
