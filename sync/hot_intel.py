from __future__ import annotations

import html
import math
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import parse_qs, quote, quote_plus, urljoin, urlparse, unquote

from sync.common import FetchError, fetch_text


DUCKDUCKGO_URL = "https://html.duckduckgo.com/html/"
HATENA_SEARCH_URL = "https://b.hatena.ne.jp/q/"
HATENA_DEFAULT_USERS = 20
HATENA_DEFAULT_DATE_RANGE = "m"
HATENA_DEFAULT_SORT = "popular"
HATENA_DEFAULT_TARGET = "text"
DEFAULT_USER_AGENT = "vulnsignal/0.1"
X_DOMAINS = ("x.com", "twitter.com")
NEWS_DOMAINS = (
    "thehackernews.com",
    "scworld.com",
    "bleepingcomputer.com",
    "therecord.media",
    "darkreading.com",
    "securityweek.com",
    "krebsonsecurity.com",
    "helpnetsecurity.com",
    "securityonline.info",
    "tomsguide.com",
    "techcrunch.com",
)
VENDOR_HINTS = (
    "advisory",
    "security bulletin",
    "security update",
    "cve-",
    "vulnerability",
    "mitigation",
    "warning",
)
DEFAULT_SIGNAL_QUERY_TERMS = (
    "active exploitation",
    "in the wild",
    "PoC",
    "zero-day",
)
JAPANESE_SIGNAL_QUERY_TERMS = (
    "悪用",
    "実際に悪用",
    "公開PoC",
    "実証コード",
    "ゼロデイ",
    "既知の悪用",
)
DEFAULT_BROADEN_QUERY_TERMS = (
    "CVE-2026",
    "CVE-2025",
    "exploit",
    "weaponized",
    "vulnerability",
    "悪用",
    "公開PoC",
    "ゼロデイ",
)

RESULT_RE = re.compile(
    r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
GENERIC_QUERY_HINTS = (
    "vulnerability",
    "issue",
    "flaw",
    "weakness",
    "advisory",
    "security",
    "update",
    "cve",
)
RSS_FEEDS = (
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("SecurityOnline", "https://securityonline.info/feed/"),
    ("HelpNetSecurity", "https://www.helpnetsecurity.com/feed/"),
    ("CISA Advisories", "https://www.cisa.gov/cybersecurity-advisories/all.xml"),
    ("WeLiveSecurity", "https://www.welivesecurity.com/feed/"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
)


@dataclass(frozen=True)
class HotCandidate:
    vuln_id: str
    source: str
    title: str | None
    severity: str | None
    cvss_score: float | None
    published_at: str | None
    first_seen_at: str | None


@dataclass(frozen=True)
class SearchHit:
    query: str
    title: str
    url: str
    domain: str
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class HotEvidence:
    evidence_type: str
    source_type: str
    weight: float
    url: str
    title: str
    domain: str
    query: str
    matched_terms: list[str]


def canonicalize_url(href: str) -> str:
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    if parsed.netloc.endswith("duckduckgo.com") and parsed.path.startswith("/l/"):
        query = parse_qs(parsed.query)
        if "uddg" in query and query["uddg"]:
            return unquote(query["uddg"][0])
    return href


def normalize_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.lower()


def strip_tags(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", html.unescape(text)).strip()


def extract_cve_ids(text: str | None) -> list[str]:
    if not text:
        return []
    return list(dict.fromkeys(match.upper() for match in CVE_RE.findall(text)))


def _normalize_search_phrase(text: str | None) -> str | None:
    if not text:
        return None
    cleaned = " ".join(text.split())
    cleaned = re.sub(r"\bCVE-\d{4}-\d{4,7}\b", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\b(?:%s)\b" % "|".join(re.escape(item) for item in GENERIC_QUERY_HINTS), "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" -,:;")
    if not cleaned:
        return None
    return cleaned[:120]


def _broaden_search_phrase(text: str | None) -> str | None:
    if not text:
        return None
    cleaned = re.sub(r"\bdenial of service\b", "", text, flags=re.IGNORECASE)
    cleaned = re.sub(r"\bdos\b", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" -,:;")
    if not cleaned:
        return None
    if cleaned == text:
        return None
    return cleaned[:120]


@lru_cache(maxsize=4096)
def search_duckduckgo(query: str, results_per_query: int = 10) -> list[SearchHit]:
    url = f"{DUCKDUCKGO_URL}?q={quote_plus(query)}"
    text = fetch_text(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    hits: list[SearchHit] = []
    seen_urls: set[str] = set()
    for match in RESULT_RE.finditer(text):
        href = canonicalize_url(html.unescape(match.group("href")))
        title = strip_tags(match.group("title"))
        if not title or not href:
            continue
        if href in seen_urls:
            continue
        seen_urls.add(href)
        hits.append(SearchHit(query=query, title=title, url=href, domain=normalize_domain(href)))
        if len(hits) >= results_per_query:
            break
    return hits


ENTRY_SEARCH_ITEM_RE = re.compile(
    r'<li[^>]*class="[^"]*\bbookmark-item\b[^"]*"[^>]*>(?P<body>.*?)</li>',
    re.IGNORECASE | re.DOTALL,
)
ENTRY_SEARCH_TITLE_RE = re.compile(
    r'<h3[^>]*class="[^"]*\bcenterarticle-entry-title\b[^"]*"[^>]*>\s*<a[^>]*href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
ENTRY_SEARCH_USERS_RE = re.compile(
    r'<a[^>]*href="(?P<href>[^"]+)"[^>]*data-gtm-click-label="entry-search-result-item-users"[^>]*>\s*(?P<users>\d+)\s+users?\s*</a>',
    re.IGNORECASE | re.DOTALL,
)


def search_hatena(
    query: str,
    results_per_query: int = 10,
    users: int = HATENA_DEFAULT_USERS,
    date_range: str = HATENA_DEFAULT_DATE_RANGE,
    sort: str = HATENA_DEFAULT_SORT,
    target: str = HATENA_DEFAULT_TARGET,
) -> list[SearchHit]:
    url = (
        f"{HATENA_SEARCH_URL}{quote(query, safe='')}"
        f"?users={users}&sort={quote_plus(sort)}&date_range={quote_plus(date_range)}"
        f"&safe=on&target={quote_plus(target)}"
    )
    text = fetch_text(url, headers={"User-Agent": DEFAULT_USER_AGENT})
    hits: list[SearchHit] = []
    seen_urls: set[str] = set()
    for match in ENTRY_SEARCH_ITEM_RE.finditer(text):
        body = match.group("body")
        title_match = ENTRY_SEARCH_TITLE_RE.search(body)
        users_match = ENTRY_SEARCH_USERS_RE.search(body)
        if not title_match or not users_match:
            continue
        target_url = canonicalize_url(html.unescape(title_match.group("href")))
        hatena_url = canonicalize_url(html.unescape(users_match.group("href")))
        if hatena_url.startswith("/"):
            hatena_url = urljoin(HATENA_SEARCH_URL, hatena_url)
        title = strip_tags(title_match.group("title"))
        if not hatena_url or not title or hatena_url in seen_urls:
            continue
        try:
            hatena_users = int(users_match.group("users"))
        except (TypeError, ValueError):
            continue
        body_text = strip_tags(body)
        cve_ids = extract_cve_ids(" ".join(part for part in (title, body_text, target_url) if part))
        seen_urls.add(hatena_url)
        hits.append(
            SearchHit(
                query=url,
                title=title,
                url=hatena_url,
                domain=normalize_domain(hatena_url),
                metadata={
                    "source_label": "Hatena Bookmark",
                    "hatena_users": hatena_users,
                    "cve_ids": cve_ids,
                    "body_text": body_text,
                    "target_url": target_url,
                },
            )
        )
        if len(hits) >= results_per_query:
            break
    return hits


def hot_queries(title: str | None = None, summary: str | None = None) -> list[str]:
    title_phrase = _normalize_search_phrase(title)
    summary_phrase = _normalize_search_phrase(summary)
    seed = title_phrase or summary_phrase
    if not seed:
        return []

    broad_seed = _broaden_search_phrase(seed) or seed
    queries = [f'"{broad_seed}"']
    queries.append(f'"{broad_seed}" exploit OR PoC OR "active exploitation"')
    queries.append(f'"{broad_seed}" 悪用 OR 公開PoC OR 実証コード OR ゼロデイ')
    if seed != broad_seed:
        queries.append(f'"{seed}" exploit OR PoC OR "active exploitation"')
        queries.append(f'"{seed}" 悪用 OR 公開PoC OR 実証コード OR ゼロデイ')
    elif summary_phrase and summary_phrase != seed:
        queries.append(f'"{summary_phrase}" exploit OR PoC OR "active exploitation"')
        queries.append(f'"{summary_phrase}" 悪用 OR 公開PoC OR 実証コード OR ゼロデイ')
    queries.append(f'site:x.com "{broad_seed}"')
    return queries


def _xml_text(element: ET.Element, *names: str) -> str | None:
    for name in names:
        child = element.find(name)
        if child is not None and child.text:
            text = " ".join(child.text.split()).strip()
            if text:
                return text
    return None


def fetch_rss_feed_items(
    feed_name: str,
    feed_url: str,
    results_per_query: int = 10,
    follow_article_links: bool = True,
) -> list[dict[str, Any]]:
    xml = fetch_text(feed_url, headers={"User-Agent": DEFAULT_USER_AGENT})
    root = ET.fromstring(xml)
    items: list[dict[str, Any]] = []

    if root.tag.endswith("rss"):
        entry_nodes = root.findall("./channel/item")
    else:
        entry_nodes = root.findall(".//{http://www.w3.org/2005/Atom}entry")

    for entry in entry_nodes:
        title = _xml_text(entry, "title", "{http://www.w3.org/2005/Atom}title")
        link = _xml_text(entry, "link", "{http://www.w3.org/2005/Atom}link")
        if not link:
            link_el = entry.find("{http://www.w3.org/2005/Atom}link")
            if link_el is not None:
                link = link_el.attrib.get("href")
        description = _xml_text(entry, "description", "content", "{http://purl.org/rss/1.0/modules/content/}encoded")
        published_at = _xml_text(entry, "pubDate", "published", "updated")
        if not title or not link:
            continue
        summary = strip_tags(description or "")
        full_text = " ".join(part for part in (title, summary, link) if part)
        cve_ids = extract_cve_ids(full_text)
        if not cve_ids and follow_article_links:
            try:
                article_html = fetch_text(link, headers={"User-Agent": DEFAULT_USER_AGENT})
                article_text = strip_tags(article_html)
                cve_ids = extract_cve_ids(" ".join(part for part in (title, summary, article_text, link) if part))
            except FetchError:
                cve_ids = []
        items.append(
            {
                "feed": feed_name,
                "query": feed_url,
                "title": strip_tags(title),
                "summary": summary,
                "url": link,
                "domain": normalize_domain(link),
                "published_at": published_at,
                "cve_ids": cve_ids,
            }
        )
        if len(items) >= results_per_query:
            break
    return items


def _normalize_query_terms(query_terms: list[str] | None) -> list[str]:
    terms: list[str] = []
    for term in query_terms or []:
        phrase = _normalize_search_phrase(term)
        if phrase:
            terms.append(phrase)
    return list(dict.fromkeys(terms))


def _build_discovery_queries(query_terms: list[str] | None) -> list[str]:
    queries: list[str] = []
    for term in query_terms or []:
        phrase = term
        queries.extend(
            [
                f'"{phrase}"',
                f'"{phrase}" exploit OR PoC OR "active exploitation"',
                f'"{phrase}" 悪用 OR 公開PoC OR 実証コード OR ゼロデイ',
                f'site:cisa.gov "{phrase}"',
                f'site:thehackernews.com "{phrase}"',
            ]
        )
    return list(dict.fromkeys(queries))


def discover_hot_candidates(
    results_per_query: int = 10,
    max_candidates: int = 20,
    query_terms: list[str] | None = None,
    follow_article_links: bool = True,
    enable_duckduckgo: bool = True,
    enable_hatena: bool = True,
) -> dict[str, Any]:
    candidate_ids: list[str] = []
    seen_ids: set[str] = set()
    hits: list[dict[str, Any]] = []
    search_queries: list[str] = []
    fetch_errors: list[dict[str, str]] = []
    explicit_query_terms = _normalize_query_terms(query_terms)
    baseline_query_terms = list(DEFAULT_SIGNAL_QUERY_TERMS)
    baseline_query_terms.extend(JAPANESE_SIGNAL_QUERY_TERMS)
    if explicit_query_terms:
        baseline_query_terms.extend(explicit_query_terms)
        baseline_query_terms = list(dict.fromkeys(baseline_query_terms))

    for feed_name, feed_url in RSS_FEEDS:
        search_queries.append(feed_url)
        try:
            feed_items = fetch_rss_feed_items(
                feed_name,
                feed_url,
                results_per_query=results_per_query,
                follow_article_links=follow_article_links,
            )
        except FetchError as exc:
            fetch_errors.append({"feed": feed_name, "query": feed_url, "error": str(exc)})
            continue

        for item in feed_items:
            hits.append(item)
            for vuln_id in item["cve_ids"]:
                if vuln_id in seen_ids:
                    continue
                seen_ids.add(vuln_id)
                candidate_ids.append(vuln_id)
                if len(candidate_ids) >= max_candidates:
                    break
            if len(candidate_ids) >= max_candidates:
                break
        if len(candidate_ids) >= max_candidates:
            break

    if enable_duckduckgo:
        for query in _build_discovery_queries(baseline_query_terms):
            search_queries.append(query)
            try:
                query_hits = search_duckduckgo(query, results_per_query=results_per_query)
            except FetchError:
                continue
            for hit in query_hits:
                metadata = hit.metadata or {}
                cve_ids = list(metadata.get("cve_ids") or [])
                if not cve_ids:
                    cve_ids = extract_cve_ids(f"{hit.title} {hit.url}")
                if not cve_ids:
                    continue
                item = {
                    "feed": "DuckDuckGo",
                    "query": query,
                    "title": hit.title,
                    "summary": "",
                    "url": hit.url,
                    "domain": hit.domain,
                    "published_at": None,
                    "cve_ids": cve_ids,
                }
                hits.append(item)
                for vuln_id in cve_ids:
                    if vuln_id in seen_ids:
                        continue
                    seen_ids.add(vuln_id)
                    candidate_ids.append(vuln_id)
                    if len(candidate_ids) >= max_candidates:
                        break
                if len(candidate_ids) >= max_candidates:
                    break
            if len(candidate_ids) >= max_candidates:
                break

        if not explicit_query_terms and len(candidate_ids) < max(5, max_candidates // 2):
            for query in _build_discovery_queries(list(DEFAULT_BROADEN_QUERY_TERMS)):
                search_queries.append(query)
                try:
                    query_hits = search_duckduckgo(query, results_per_query=results_per_query)
                except FetchError:
                    continue
                for hit in query_hits:
                    cve_ids = extract_cve_ids(f"{hit.title} {hit.url}")
                    if not cve_ids:
                        continue
                    item = {
                        "feed": "DuckDuckGo",
                        "query": query,
                        "title": hit.title,
                        "summary": "",
                        "url": hit.url,
                        "domain": hit.domain,
                        "published_at": None,
                        "cve_ids": cve_ids,
                    }
                    hits.append(item)
                    for vuln_id in cve_ids:
                        if vuln_id in seen_ids:
                            continue
                        seen_ids.add(vuln_id)
                        candidate_ids.append(vuln_id)
                        if len(candidate_ids) >= max_candidates:
                            break
                    if len(candidate_ids) >= max_candidates:
                        break
                if len(candidate_ids) >= max_candidates:
                    break

    if enable_hatena and len(candidate_ids) < max_candidates:
        for term in baseline_query_terms:
            search_query = (
                f"{HATENA_SEARCH_URL}{quote(term, safe='')}"
                f"?users={HATENA_DEFAULT_USERS}&sort={HATENA_DEFAULT_SORT}"
                f"&date_range={HATENA_DEFAULT_DATE_RANGE}&safe=on&target={HATENA_DEFAULT_TARGET}"
            )
            search_queries.append(search_query)
            try:
                query_hits = search_hatena(term, results_per_query=results_per_query)
            except FetchError:
                continue
            for hit in query_hits:
                metadata = hit.metadata or {}
                cve_ids = list(metadata.get("cve_ids") or [])
                if not cve_ids:
                    cve_ids = extract_cve_ids(f"{hit.title} {hit.url}")
                if not cve_ids:
                    continue
                item = {
                    "feed": "Hatena Bookmark",
                    "query": search_query,
                    "title": hit.title,
                    "summary": "",
                    "url": hit.url,
                    "domain": hit.domain,
                    "published_at": None,
                    "cve_ids": cve_ids,
                }
                hits.append(item)
                for vuln_id in cve_ids:
                    if vuln_id in seen_ids:
                        continue
                    seen_ids.add(vuln_id)
                    candidate_ids.append(vuln_id)
                    if len(candidate_ids) >= max_candidates:
                        break
                if len(candidate_ids) >= max_candidates:
                    break
            if len(candidate_ids) >= max_candidates:
                break

    return {
        "query_count": len(search_queries),
        "search_queries": search_queries,
        "result_count": len(hits),
        "discovered_vuln_ids": candidate_ids,
        "search_hits": hits[:10],
        "urls": [item["url"] for item in hits[:10]],
        "fetch_errors": fetch_errors,
    }


def _match_terms(text: str) -> list[str]:
    normalized = text.lower()
    terms = []
    for term in (
        "active exploitation",
        "actively exploited",
        "in the wild",
        "proof of concept",
        "poc",
        "exploit",
        "weaponized",
        "kev",
        "悪用",
        "実際に悪用",
        "公開poc",
        "実証コード",
        "ゼロデイ",
        "既知の悪用",
    ):
        if term in normalized:
            terms.append(term)
    return terms


NEGATION_RE = re.compile(
    r"\b(?:no|not|without|never|none|lack|lacks|lacking|absence|absent)\b(?:\W+\w+){0,3}\W*$",
    re.IGNORECASE,
)


def _contains_positive_phrase(text: str, phrase: str) -> bool:
    normalized = text.lower()
    phrase_re = re.compile(re.escape(phrase.lower()))
    for match in phrase_re.finditer(normalized):
        prefix = normalized[max(0, match.start() - 120) : match.start()]
        if NEGATION_RE.search(prefix):
            continue
        return True
    return False


def classify_hit(hit: SearchHit) -> HotEvidence | None:
    content_text = f"{hit.title} {hit.url}".lower()
    query_text = hit.query.lower()
    search_text = f"{content_text} {query_text}"
    matched_terms = _match_terms(search_text)
    domain = hit.domain

    evidence_type: str | None = None
    source_type = "other"
    weight = 0.0

    if "cisa.gov" in domain and ("known exploited vulnerabilities" in content_text or "kev" in content_text):
        evidence_type = "kev"
        source_type = "cisa"
        weight = 1.0
    elif "cisa.gov" in domain:
        source_type = "cisa"
        if "active exploitation" in content_text or "actively exploited" in content_text:
            evidence_type = "active_exploitation"
            weight = 0.95
        elif "proof of concept" in content_text or "poc" in content_text or "exploit" in content_text or "weaponized" in content_text:
            evidence_type = "public_poc"
            weight = 0.8
        elif any(needle in content_text for needle in ("advisory", "alert", "vulnerability")):
            evidence_type = "news_mention"
            weight = 0.55
    elif any(domain.endswith(part) or f".{part}" in domain for part in X_DOMAINS):
        evidence_type = "x_mention"
        source_type = "social"
        weight = 0.25
    elif any(part in domain for part in NEWS_DOMAINS):
        source_type = "news"
        if (
            _contains_positive_phrase(content_text, "active exploitation")
            or _contains_positive_phrase(content_text, "actively exploited")
            or _contains_positive_phrase(content_text, "in the wild")
        ):
            evidence_type = "active_exploitation"
            weight = 0.95
        elif (
            _contains_positive_phrase(content_text, "proof of concept")
            or re.search(r"\bpoc\b", content_text)
            or _contains_positive_phrase(content_text, "exploit")
            or _contains_positive_phrase(content_text, "weaponized")
        ):
            evidence_type = "public_poc"
            weight = 0.75
        else:
            evidence_type = "news_mention"
            weight = 0.45
    elif any(needle in content_text for needle in ("advisory", "security update", "security bulletin", "mitigation")):
        evidence_type = "vendor_advisory"
        source_type = "vendor"
        if _contains_positive_phrase(content_text, "active exploitation") or _contains_positive_phrase(content_text, "actively exploited"):
            weight = 0.9
        elif _contains_positive_phrase(content_text, "exploit") or re.search(r"\bpoc\b", content_text) or _contains_positive_phrase(content_text, "proof of concept"):
            weight = 0.7
        else:
            weight = 0.65
    elif matched_terms:
        if (
            _contains_positive_phrase(search_text, "active exploitation")
            or _contains_positive_phrase(search_text, "actively exploited")
            or _contains_positive_phrase(search_text, "in the wild")
        ):
            evidence_type = "active_exploitation"
            source_type = "search"
            weight = 0.82
        elif (
            _contains_positive_phrase(search_text, "proof of concept")
            or re.search(r"\bpoc\b", search_text)
            or _contains_positive_phrase(search_text, "exploit")
            or _contains_positive_phrase(search_text, "weaponized")
        ):
            evidence_type = "public_poc"
            source_type = "search"
            weight = 0.6
        else:
            evidence_type = "mention"
            source_type = "search"
            weight = 0.2
    elif "b.hatena.ne.jp" in domain or "bookmark.hatena.ne.jp" in domain:
        evidence_type = "hatena_popular"
        source_type = "social"
        hatena_users = None
        metadata = getattr(hit, "metadata", None)
        if isinstance(metadata, dict):
            raw_users = metadata.get("hatena_users")
            try:
                hatena_users = int(raw_users) if raw_users is not None else None
            except (TypeError, ValueError):
                hatena_users = None
        if hatena_users is not None and hatena_users > 0:
            weight = min(0.65, 0.45 + min(0.18, math.log2(hatena_users + 1) * 0.02))
        else:
            weight = 0.55

    if evidence_type is None:
        return None

    return HotEvidence(
        evidence_type=evidence_type,
        source_type=source_type,
        weight=weight,
        url=hit.url,
        title=hit.title,
        domain=domain,
        query=hit.query,
        matched_terms=matched_terms,
    )


def _confidence_score(evidence: list[HotEvidence]) -> float:
    if not evidence:
        return 0.0
    peak = max(item.weight for item in evidence)
    source_count = len({item.domain for item in evidence})
    evidence_count = len(evidence)
    source_bonus = min(0.12, 0.04 * math.log2(source_count + 1))
    count_bonus = min(0.10, 0.03 * math.log2(evidence_count + 1))
    score = peak * 0.76 + source_bonus + count_bonus
    if any(item.evidence_type == "kev" for item in evidence):
        score += 0.03
    elif any(item.evidence_type == "active_exploitation" for item in evidence):
        score += 0.02
    elif any(item.evidence_type == "public_poc" for item in evidence):
        score += 0.01
    return round(min(0.97, score), 2)


def attention_score_from_value(value: dict[str, Any] | None) -> float | None:
    if not value:
        return None
    details = value.get("evidence_details") or []
    if not isinstance(details, list):
        details = []

    weights: list[float] = []
    domains: set[str] = set()
    evidence_types: set[str] = set()
    for item in details:
        if not isinstance(item, dict):
            continue
        weight = item.get("weight")
        if weight is not None:
            try:
                weights.append(float(weight))
            except (TypeError, ValueError):
                continue
        domain = item.get("domain")
        if domain:
            domains.add(str(domain))
        evidence_type = item.get("evidence_type")
        if evidence_type:
            evidence_types.add(str(evidence_type))

    if weights:
        peak = max(weights)
        source_count = len(domains)
        evidence_count = len(details)
    else:
        evidence_types = {str(item) for item in (value.get("evidence_types") or []) if item}
        peak_lookup = {
            "kev": 1.0,
            "active_exploitation": 0.95,
            "public_poc": 0.75,
            "vendor_advisory": 0.65,
            "news_mention": 0.45,
            "hatena_popular": 0.55,
            "x_mention": 0.25,
            "mention": 0.20,
        }
        peak = max((peak_lookup.get(item, 0.0) for item in evidence_types), default=0.0)
        if not peak:
            return None
        source_count = int(value.get("independent_sources") or 1)
        evidence_count = int(value.get("evidence_count") or 1)

    source_bonus = min(0.12, 0.04 * math.log2(source_count + 1))
    count_bonus = min(0.10, 0.03 * math.log2(evidence_count + 1))
    score = peak * 0.76 + source_bonus + count_bonus
    if "kev" in evidence_types or peak >= 1.0:
        score += 0.03
    elif "active_exploitation" in evidence_types:
        score += 0.02
    elif "public_poc" in evidence_types:
        score += 0.01
    return round(min(0.97, score), 2)


def collect_hot_evidence_for_vuln(
    vuln_id: str,
    title: str | None = None,
    summary: str | None = None,
    queries_per_vuln: int = 3,
    results_per_query: int = 10,
    hits: list[SearchHit] | None = None,
) -> dict[str, Any] | None:
    queries: list[str]
    if hits is not None:
        queries = list(dict.fromkeys(hit.query for hit in hits if hit.query))
        unique_hits = []
        seen_urls: set[str] = set()
        for hit in hits:
            if hit.url in seen_urls:
                continue
            seen_urls.add(hit.url)
            unique_hits.append(hit)
    else:
        queries = hot_queries(title, summary)
        queries = queries[: max(1, queries_per_vuln)]
        hits = []
        for query in queries:
            hits.extend(search_duckduckgo(query, results_per_query=results_per_query))

        hatena_seed = _normalize_search_phrase(title) or _normalize_search_phrase(summary)
        if hatena_seed:
            try:
                hits.extend(search_hatena(hatena_seed, results_per_query=results_per_query))
            except FetchError:
                pass

        unique_hits = []
        seen_urls: set[str] = set()
        for hit in hits:
            if hit.url in seen_urls:
                continue
            seen_urls.add(hit.url)
            unique_hits.append(hit)

    evidence = [item for item in (classify_hit(hit) for hit in unique_hits) if item is not None]
    if not evidence:
        return None

    evidence.sort(key=lambda item: (item.weight, item.domain, item.url), reverse=True)
    score = _confidence_score(evidence)
    search_queries = queries
    hit_details = [
        {
            "query": hit.query,
            "title": hit.title,
            "url": hit.url,
            "domain": hit.domain,
            "source_label": (hit.metadata or {}).get("source_label"),
        }
        for hit in unique_hits[:10]
    ]
    evidence_details = [
        {
            "evidence_type": item.evidence_type,
            "source_type": item.source_type,
            "source_label": "Hatena Bookmark" if item.evidence_type == "hatena_popular" else None,
            "weight": item.weight,
            "url": item.url,
            "title": item.title,
            "domain": item.domain,
            "query": item.query,
            "matched_terms": item.matched_terms,
        }
        for item in evidence[:10]
    ]
    return {
        "score": score,
        "query_count": len(queries),
        "search_queries": search_queries,
        "result_count": len(unique_hits),
        "evidence_count": len(evidence),
        "independent_sources": len({item.domain for item in evidence}),
        "evidence_types": sorted({item.evidence_type for item in evidence}),
        "source_types": sorted({item.source_type for item in evidence}),
        "urls": [item.url for item in evidence[:10]],
        "search_hits": hit_details,
        "evidence_details": evidence_details,
        "headline": evidence[0].title,
    }
