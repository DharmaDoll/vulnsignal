from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, quote_plus, urlparse, unquote

from sync.common import FetchError, fetch_text


DUCKDUCKGO_URL = "https://html.duckduckgo.com/html/"
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

RESULT_RE = re.compile(
    r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="(?P<href>[^"]+)"[^>]*>(?P<title>.*?)</a>',
    re.IGNORECASE | re.DOTALL,
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


def search_duckduckgo(query: str, results_per_query: int = 5) -> list[SearchHit]:
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


def hot_queries(vuln_id: str, title: str | None = None) -> list[str]:
    queries = [
        f'"{vuln_id}"',
        f'"{vuln_id}" exploit OR PoC OR "active exploitation"',
        f'site:x.com "{vuln_id}"',
    ]
    if title:
        compact_title = " ".join(title.split())
        if compact_title:
            queries.insert(1, f'"{vuln_id}" "{compact_title[:90]}"')
    return queries


def _match_terms(text: str) -> list[str]:
    normalized = text.lower()
    terms = []
    for term in ("active exploitation", "actively exploited", "in the wild", "proof of concept", "poc", "exploit", "weaponized", "kev"):
        if term in normalized:
            terms.append(term)
    return terms


def classify_hit(hit: SearchHit) -> HotEvidence | None:
    text = f"{hit.title} {hit.url}".lower()
    matched_terms = _match_terms(text)
    domain = hit.domain

    evidence_type: str | None = None
    source_type = "other"
    weight = 0.0

    if "cisa.gov" in domain and ("known exploited vulnerabilities" in text or "kev" in text):
        evidence_type = "kev"
        source_type = "cisa"
        weight = 1.0
    elif any(domain.endswith(part) or f".{part}" in domain for part in X_DOMAINS):
        evidence_type = "x_mention"
        source_type = "social"
        weight = 0.25
    elif any(part in domain for part in NEWS_DOMAINS):
        source_type = "news"
        if "active exploitation" in text or "actively exploited" in text or "in the wild" in text:
            evidence_type = "active_exploitation"
            weight = 0.95
        elif "proof of concept" in text or "poc" in text or "exploit" in text or "weaponized" in text:
            evidence_type = "public_poc"
            weight = 0.75
        else:
            evidence_type = "news_mention"
            weight = 0.45
    elif any(needle in text for needle in ("advisory", "security update", "security bulletin", "mitigation")):
        evidence_type = "vendor_advisory"
        source_type = "vendor"
        if "active exploitation" in text or "actively exploited" in text:
            weight = 0.9
        elif "exploit" in text or "poc" in text or "proof of concept" in text:
            weight = 0.7
        else:
            weight = 0.65
    elif matched_terms:
        evidence_type = "mention"
        source_type = "search"
        weight = 0.2

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
    source_bonus = min(0.2, 0.05 * (len({item.domain for item in evidence}) - 1))
    count_bonus = min(0.2, 0.05 * max(0, len(evidence) - 1))
    return round(min(1.0, peak + source_bonus + count_bonus), 2)


def collect_hot_evidence_for_vuln(
    vuln_id: str,
    title: str | None = None,
    queries_per_vuln: int = 3,
    results_per_query: int = 5,
) -> dict[str, Any] | None:
    queries = hot_queries(vuln_id, title)
    queries = queries[: max(1, queries_per_vuln)]
    hits: list[SearchHit] = []
    for query in queries:
        hits.extend(search_duckduckgo(query, results_per_query=results_per_query))

    unique_hits: list[SearchHit] = []
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
    return {
        "score": score,
        "query_count": len(queries),
        "result_count": len(unique_hits),
        "evidence_count": len(evidence),
        "independent_sources": len({item.domain for item in evidence}),
        "evidence_types": sorted({item.evidence_type for item in evidence}),
        "source_types": sorted({item.source_type for item in evidence}),
        "urls": [item.url for item in evidence[:10]],
        "headline": evidence[0].title,
    }

