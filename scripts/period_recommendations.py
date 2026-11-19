"""Generate and replay calendar-period recommendations from observed feed evidence."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import tempfile
from itertools import groupby
from collections import defaultdict
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from sync.hot_intel import reviewed_hot_value
from db.migrate import migrate
from sync.common import DB_PATH, ROOT, connect
from sync.feed_quality import MAX_STALENESS_HOURS

THEMES = ROOT / "config" / "watch_themes.json"
PROVIDERS = {
    "CISA KEV": "kev", "CVE Program": "cve_program", "GitHub Advisory Database": "ghsa",
    "Web Hot Intel": "hot", "go-exploitdb": "go-exploitdb", "CISA Vulnrichment": "vulnrichment",
}
FIELDS = ("title", "summary", "headline", "vendor_project", "product", "package_name", "ecosystem",
          "fixed_version", "date_added", "published_at", "references", "url", "urls", "ghsa_id",
          "aliases", "severity", "cvss_score", "source_path", "exploit_type", "exploit_unique_id")
EXPLOIT_FAMILIES = {"GitHub": "githubrepos", "AwesomePoc": "awesomepoc", "InTheWild": "inthewild",
                    "Nuclei": "nuclei"}


def excluded_event(event, excluded):
    if PROVIDERS[event["provider"]] in excluded:
        return True
    if event["provider"] != "go-exploitdb":
        return False
    source_id = str(event["value"].get("exploit_unique_id") or "")
    family = "exploitdb" if source_id.isdecimal() else EXPLOIT_FAMILIES.get(source_id.split("-")[0])
    return family is not None and f"go-exploitdb/{family}" in excluded


RULE_VERSION = 2


def bounds(period, day, zone):
    start = datetime.combine(day, datetime.min.time(), zone)
    if period == "week":
        start -= timedelta(days=start.weekday())
    if period in ("month", "quarter"):
        month = start.month if period == "month" else 1 + 3 * ((start.month - 1) // 3)
        start = start.replace(month=month, day=1)
        next_month = month + (1 if period == "month" else 3)
        end = start.replace(year=start.year + (next_month - 1) // 12, month=(next_month - 1) % 12 + 1)
    else:
        end = start + timedelta(days=7 if period == "week" else 1)
    return start, end


def capture(db_path, start, end, cutoff):
    """Use append-only provider evidence. Mutable vulnerability rows have mixed provenance."""
    migrate(db_path)
    with closing(connect(db_path)) as conn:
        conn.execute("BEGIN")
        providers = tuple(PROVIDERS)
        placeholders = ",".join("?" for _ in providers)
        # Fetch earlier observations only for IDs with activity in the selected period.
        rows = conn.execute(f"""
            WITH active AS (
                SELECT DISTINCT vuln_id FROM signals
                WHERE julianday(observed_at) >= julianday(?) AND julianday(observed_at) < julianday(?)
                  AND provider IN ({placeholders})
            )
            SELECT s.id,s.vuln_id,s.provider,s.signal_type,s.value_json,s.score,s.observed_at
            FROM active JOIN signals s ON s.vuln_id=active.vuln_id
            WHERE julianday(s.observed_at) < julianday(?) AND s.provider IN ({placeholders})
            ORDER BY s.vuln_id,julianday(s.observed_at),s.id
        """, (start, cutoff, *providers, cutoff, *providers))
        period_start = datetime.fromisoformat(start)
        evidence = []
        for _, group in groupby(rows, key=lambda row: row["vuln_id"]):
            history = []
            active = False
            for row in group:
                value = json.loads(row["value_json"] or "{}")
                # Older Vulnrichment signals copied fields from the merged CVE row.
                if row["provider"] == "CISA Vulnrichment" and not value.get("source_fields_version"):
                    continue
                if row["signal_type"] == "hot":
                    value = reviewed_hot_value(row["vuln_id"], value)
                    if not value:
                        continue
                entry = {
                    "id": row["id"], "vuln_id": row["vuln_id"], "provider": row["provider"],
                    "type": row["signal_type"], "observed_at": row["observed_at"], "score": row["score"],
                    "value": {k: value[k] for k in FIELDS if value.get(k) is not None},
                }
                history.append(entry)
                if event_reason(entry)[0] and datetime.fromisoformat(row["observed_at"]) >= period_start:
                    active = True
            if active:
                evidence.extend(history)
        # The current EPSS table cannot reconstruct overwritten historical values.
        # Include only values demonstrably observed before the decision cutoff.
        epss = {}
        candidate_ids = sorted({event["vuln_id"] for event in evidence})
        for offset in range(0, len(candidate_ids), 500):
            ids = candidate_ids[offset:offset + 500]
            marks = ",".join("?" for _ in ids)
            for row in conn.execute(f"""
                SELECT vuln_id,epss,score_date,updated_at FROM epss_current
                WHERE vuln_id IN ({marks}) AND julianday(updated_at) < julianday(?)
            """, (*ids, cutoff)):
                epss[row["vuln_id"]] = dict(row)
        coverage = {}
        for feed in (*PROVIDERS.values(), "epss"):
            logs = conn.execute("""
                SELECT attempted_at,status,cache_used FROM fetch_log WHERE feed=?
                AND julianday(attempted_at) >= julianday(?) - ? / 24.0
                AND julianday(attempted_at) < julianday(?) ORDER BY julianday(attempted_at),id
            """, (feed, start, MAX_STALENESS_HOURS[feed], cutoff))
            coverage[feed] = [dict(row) for row in logs]
    return {"start": start, "end": end, "cutoff": cutoff, "evidence": evidence, "coverage": coverage, "epss": epss,
            "freshness_hours": {feed: MAX_STALENESS_HOURS[feed] for feed in coverage}}


def event_reason(event):
    value = event["value"]
    kind = event["type"]
    if kind == "kev":
        return 4, "KEV掲載を観測", value.get("date_added")
    if kind == "exploit" and value.get("url"):
        return 3, "公開されたexploit関連資料を観測", value["url"]
    if kind == "hot" and value.get("urls"):
        return 2, "報道・公告を観測", tuple(sorted(set(value["urls"])))
    if kind == "package_advisory" and value.get("fixed_version"):
        return 1, "修正版情報を観測", (value.get("package_name"), value["fixed_version"])
    if kind == "enrichment" and float(value.get("cvss_score") or 0) >= 9:
        return 2, "重大な深刻度評価を観測", value["cvss_score"]
    return 0, "", None


def validate_themes(themes):
    if not isinstance(themes, dict):
        raise ValueError("themes must be an object keyed by display name")
    for name, config in themes.items():
        if not name.strip() or not isinstance(config, dict) or not config.get("terms"):
            raise ValueError(f"missing terms for theme {name!r}")
        for field in ("terms", "exclude"):
            words = config.get(field, [])
            if not isinstance(words, list) or not all(isinstance(w, str) and w.strip() for w in words):
                raise ValueError(f"theme {name!r}: {field} must contain nonempty strings")


def theme_matches(values, themes):
    result = {}
    for name, config in themes.items():
        hits = set()
        for value in values:
            for field in ("product", "package_name", "title", "summary", "headline"):
                text = str(value.get(field) or "")
                def matches(term):
                    return re.search(r"(?<!\w)" + re.escape(term) + r"(?!\w)", text, re.I)
                if any(matches(term) for term in config.get("exclude", [])):
                    continue
                for term in config["terms"]:
                    if matches(term):
                        hits.add((field, term))
        if hits:
            result[name] = [{"field": f, "term": t} for f, t in sorted(hits)]
    return result


def rank(snapshot, themes, limit, excluded=(), start=None, cutoff=None):
    start = datetime.fromisoformat(start or snapshot["start"])
    cutoff = datetime.fromisoformat(cutoff or snapshot["cutoff"])
    eligible = [e for e in snapshot["evidence"] if not excluded_event(e, excluded)
                and datetime.fromisoformat(e["observed_at"]) < cutoff]
    aliases = defaultdict(set)
    for event in eligible:
        value = event["value"]
        if event["provider"] == "GitHub Advisory Database" and value.get("ghsa_id"):
            aliases[value["ghsa_id"]].update(alias for alias in value.get("aliases") or []
                                              if isinstance(alias, str) and alias.startswith("CVE-"))
    by_id = defaultdict(list)
    for event in eligible:
        vuln_id = event["vuln_id"]
        if vuln_id in aliases and len(aliases[vuln_id]) == 1:
            vuln_id = next(iter(aliases[vuln_id]))
        by_id[vuln_id].append(event)
    items = []
    for vuln_id, events in by_id.items():
        changes = []
        seen = set()
        seen_urls = set()
        headlines = set()
        values = []
        for event in sorted(events, key=lambda e: (datetime.fromisoformat(e["observed_at"]), e["id"])):
            value = event["value"]
            values.append(value)
            priority, reason, identity = event_reason(event)
            if not priority:
                continue
            if event["type"] == "hot":
                fresh = set(identity) - seen_urls
                seen_urls.update(identity)
                headline = " ".join(str(value.get("headline") or "").casefold().split())
                repeated_headline = headline and headline in headlines
                headlines.add(headline)
                if not fresh or repeated_headline:
                    continue
            key = (event["type"], json.dumps(identity, sort_keys=True))
            if key in seen:
                continue
            seen.add(key)
            if datetime.fromisoformat(event["observed_at"]) >= start:
                if event["type"] == "kev" and value.get("date_added"):
                    if str(value["date_added"])[:10] < start.date().isoformat():
                        reason = "過去のKEV掲載を新規収録"
                        priority = 1
                changes.append({"priority": priority, "reason": reason, "evidence": event})
        if changes:
            score = snapshot.get("epss", {}).get(vuln_id)
            if score and ("epss" in excluded or datetime.fromisoformat(score["updated_at"]) >= cutoff):
                score = None
            kinds = {c["evidence"]["type"] for c in changes}
            observed_days = sorted({datetime.fromisoformat(c["evidence"]["observed_at"]).astimezone(
                start.tzinfo).date().isoformat() for c in changes})
            items.append({
                "vuln_id": vuln_id, "changes": changes, "themes": theme_matches(values, themes),
                "title": next((v["title"] for v in reversed(values) if v.get("title")), vuln_id),
                "products": sorted({str(v[k]) for v in values for k in ("product", "package_name") if v.get(k)}),
                "epss": score, "observation_days": observed_days,
                "confidence_basis": sorted({c["evidence"]["provider"] for c in changes}),
                "attention_evidence_count": len({c["evidence"]["value"].get("headline") or
                    tuple(c["evidence"]["value"].get("urls", [])) for c in changes if c["evidence"]["type"] == "hot"}),
                "exploitation": "KEV confirmed" if any(e["type"] == "kev" for e in events) else "unconfirmed",
                "attention_urls": sorted(seen_urls), "change_types": sorted(kinds),
            })
    items.sort(key=lambda i: (-max(c["priority"] for c in i["changes"]),
                               -len(i["change_types"]), -(i["epss"] or {}).get("epss", 0),
                               -datetime.fromisoformat(i["changes"][-1]["evidence"]["observed_at"]).timestamp(),
                               i["vuln_id"]))
    overall = [i["vuln_id"] for i in items[:limit]]
    themed = {name: [i["vuln_id"] for i in items if name in i["themes"]][:limit] for name in themes}
    selected = set(overall).union(*themed.values())
    return {"overall": overall, "themes": themed, "items": [i for i in items if i["vuln_id"] in selected],
            "candidate_count": len(items),
            "theme_counts": {name: sum(name in i["themes"] for i in items) for name in themes}}


def coverage_gaps(snapshot, start, cutoff):
    start = datetime.fromisoformat(start)
    cutoff = datetime.fromisoformat(cutoff)
    gaps = {}
    for feed, logs in snapshot["coverage"].items():
        tolerance = timedelta(hours=snapshot.get("freshness_hours", MAX_STALENESS_HOURS)[feed])
        until = start
        missing = []
        for row in logs:
            if row["status"] != "ok" or row["cache_used"]:
                continue
            observed = datetime.fromisoformat(row["attempted_at"])
            if observed >= cutoff:
                break
            if observed > until:
                missing.append([until.isoformat(), observed.isoformat()])
            until = max(until, observed + tolerance)
        if until < cutoff:
            missing.append([until.isoformat(), cutoff.isoformat()])
        if missing:
            gaps[feed] = missing
    return gaps


def save_artifact(data, directory):
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as tmp:
        try:
            with gzip.GzipFile(filename="", fileobj=tmp, mode="wb", mtime=0, compresslevel=3) as compressed:
                with io.TextIOWrapper(compressed, encoding="utf-8") as writer:
                    json.dump(data, writer, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            tmp.flush()
            tmp.seek(0)
            digest = hashlib.file_digest(tmp, "sha256").hexdigest()
            path = directory / (digest + ".json.gz")
            os.replace(tmp.name, path)
        finally:
            Path(tmp.name).unlink(missing_ok=True)
    return path


def create_artifact(db_path, period, day, timezone_name, cutoff):
    zone = ZoneInfo(timezone_name)
    start, end = bounds(period, day or cutoff.astimezone(zone).date(), zone)
    if start > cutoff:
        raise ValueError("period starts after cutoff")
    history_start = start
    if period in ("month", "quarter"):
        history_start, _ = bounds(period, start.date() - timedelta(days=1), zone)
    snapshot = capture(db_path, history_start.isoformat(), end.isoformat(), min(end, cutoff).isoformat())
    return {"rule_version": RULE_VERSION, "period": period, "timezone": timezone_name,
            "period_start": start.isoformat(), "status": "final" if end <= cutoff else "provisional",
            "snapshot": snapshot, "themes": json.loads(THEMES.read_text()), "limit": 5}


def render(artifact):
    validate_themes(artifact["themes"])
    snapshot = artifact["snapshot"]
    start = artifact["period_start"]
    options = (snapshot, artifact["themes"], artifact["limit"], artifact.get("excluded", ()))
    report = rank(*options, start=start)
    report["coverage_gaps"] = coverage_gaps(snapshot, start, snapshot["cutoff"])
    if snapshot["start"] != start:
        previous = rank(*options, cutoff=start)
        previous_gaps = coverage_gaps(snapshot, snapshot["start"], start)
        report["previous_period"] = {
            "start": snapshot["start"], "end": start, "candidate_count": previous["candidate_count"],
            "overall": previous["overall"], "themes": previous["themes"], "items": previous["items"],
            "theme_counts": previous["theme_counts"], "coverage_gaps": previous_gaps,
            "comparable": artifact["status"] == "final" and not previous_gaps and not report["coverage_gaps"],
        }
    artifact["report"] = report
    if artifact["period"] in ("month", "quarter"):
        report["attention_timeline"] = [
            {"vuln_id": item["vuln_id"], "observations": [
                {"date": c["evidence"]["observed_at"], "urls": c["evidence"]["value"]["urls"]}
                for c in item["changes"] if c["evidence"]["type"] == "hot"
            ]} for item in report["items"] if "hot" in item["change_types"]
        ]
    return report


def print_summary(report):
    print(f"{report['period']}  {report['start']} ～ {report['cutoff']}  ({report['status']})")
    print("全体順位  " + (", ".join(report["overall"]) or "該当なし"))
    for theme, ids in report["themes"].items():
        print(f"{theme}  {', '.join(ids) or '該当なし'}")
    for item in report["items"]:
        print(f"\n{item['vuln_id']}  {item['title']}")
        # Print one example per distinct reason. The archive includes the full chronology.
        examples = {change["reason"]: change["evidence"] for change in item["changes"]}
        for reason, event in examples.items():
            v = event["value"]
            urls = v.get("references") or v.get("urls") or []
            link = v.get("url") or next(iter(urls), "") or v.get("source_path") or event["provider"]
            published = v.get("date_added") or v.get("published_at")
            date_note = f"（出典日付 {published}）" if published else ""
            print(f"  {event['observed_at']}  {reason}{date_note}  {link}")
    previous = report.get("previous_period")
    if previous:
        print(f"前期 / 当期の観測候補数  {previous['candidate_count']} / {report['candidate_count']}")
        if not previous["comparable"]:
            print("速報または観測欠損のため、増減の評価を保留")
    if report["coverage_gaps"]:
        print("観測欠損  " + ", ".join(report["coverage_gaps"]))
    if report.get("artifact"):
        print(f"保存先  {report['artifact']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--period", choices=("day", "week", "month", "quarter"), default="day")
    parser.add_argument("--date", type=date.fromisoformat)
    parser.add_argument("--timezone", default="Asia/Tokyo")
    parser.add_argument("--as-of", type=datetime.fromisoformat)
    parser.add_argument("--themes", type=Path)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--db-path", type=Path, default=DB_PATH)
    parser.add_argument("--save", action="store_true", help="Save a replay archive.")
    parser.add_argument("--output-dir", type=Path, help="Save an archive in this directory.")
    parser.add_argument("--json", action="store_true", help="Print the full report as JSON.")
    parser.add_argument("--replay", type=Path)
    parser.add_argument("--exclude-feed", action="append", choices=sorted([*PROVIDERS.values(), "epss",
                        *("go-exploitdb/" + f for f in ("exploitdb", *EXPLOIT_FAMILIES.values()))]), default=[])
    args = parser.parse_args()
    if args.replay:
        with gzip.open(args.replay, "rt", encoding="utf-8") as saved:
            artifact = json.load(saved)
        if artifact["rule_version"] != RULE_VERSION:
            parser.error("unsupported snapshot rule version")
    else:
        cutoff = args.as_of or datetime.now(timezone.utc)
        if cutoff.tzinfo is None or cutoff > datetime.now(timezone.utc):
            parser.error("--as-of requires an offset and cannot be in the future")
        artifact = create_artifact(args.db_path, args.period, args.date, args.timezone, cutoff)
    if args.themes:
        artifact["themes"] = json.loads(args.themes.read_text())
    if args.limit is not None:
        artifact["limit"] = args.limit
    if artifact["limit"] < 1:
        parser.error("--limit must be positive")
    if args.exclude_feed:
        artifact["excluded"] = args.exclude_feed
    report = render(artifact)
    snapshot = artifact["snapshot"]
    start = artifact["period_start"]
    path = None
    if args.save or args.output_dir:
        path = save_artifact(artifact, args.output_dir or ROOT / "data/reports/recommendations")
    output = {"artifact": str(path) if path else None, "period": artifact["period"], "status": artifact["status"],
              "start": start, "cutoff": snapshot["cutoff"], **report}
    if args.json:
        print(json.dumps(output, ensure_ascii=False))
    else:
        print_summary(output)



if __name__ == "__main__":
    main()
