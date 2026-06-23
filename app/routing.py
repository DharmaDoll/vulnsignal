from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


VULN_ID_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


@dataclass(frozen=True)
class AgentStep:
    role: str
    task: str
    inputs: list[str]
    commands: list[str]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "task": self.task,
            "inputs": self.inputs,
            "commands": self.commands,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class RoutingPlan:
    request: str
    mode: str
    primary_agent: str
    confidence: str
    summary: str
    sub_agents: list[AgentStep]
    source_docs: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "request": self.request,
            "mode": self.mode,
            "primary_agent": self.primary_agent,
            "confidence": self.confidence,
            "summary": self.summary,
            "sub_agents": [step.to_dict() for step in self.sub_agents],
            "source_docs": self.source_docs,
        }


def _has_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


def _extract_vuln_ids(text: str) -> list[str]:
    return list(dict.fromkeys(match.group(0).upper() for match in VULN_ID_RE.finditer(text)))


def plan_request(request: str) -> RoutingPlan:
    normalized = request.strip()
    lowered = normalized.lower()
    vuln_ids = _extract_vuln_ids(normalized)
    is_single_vuln = len(vuln_ids) == 1

    deep_dive_terms = (
        "deep dive",
        "deep-dive",
        "深掘",
        "調査",
        "詳細",
        "copyfail",
        "root cause",
        "poc",
        "exploit",
    )
    watchlist_terms = (
        "watchlist",
        "今追うべき",
        "注目",
        "重要",
        "top 10",
        "top 20",
        "30件",
        "40件",
        "100件",
        "risk list",
    )
    feed_terms = (
        "feed",
        "refresh",
        "更新",
        "最新化",
        "差分",
        "staleness",
        "hot",
    )

    if is_single_vuln or _has_any(lowered, deep_dive_terms):
        vuln_label = vuln_ids[0] if vuln_ids else "single vulnerability"
        return RoutingPlan(
            request=normalized,
            mode="deep_dive",
            primary_agent="main",
            confidence="high" if is_single_vuln else "medium",
            summary=f"Use main for the conclusion and one sub-agent for {vuln_label} evidence gathering.",
            sub_agents=[
                AgentStep(
                    role="sub-agent",
                    task="Gather bounded evidence for a single CVE",
                    inputs=[
                        "db/core.db",
                        "data/aquasecurity-vuln-list-mirror",
                        "db/exploit.db",
                        "hot",
                    ],
                    commands=[
                        "uv run python scripts/deep_dive.py <CVE-ID> --json",
                        "rg -n --glob '*.json' '<CVE-ID>' data/aquasecurity-vuln-list-mirror/{alpine,debian,ubuntu,ghsa,glad,go,osv,seal}",
                        "python3 -m sync.fetch_hot --vuln-id <CVE-ID> --simple",
                    ],
                    reason="Single-vulnerability lookups benefit from one evidence-gathering worker.",
                )
            ],
            source_docs=["docs/DEEP_DIVE.md", "docs/FEEDS.md"],
        )

    if _has_any(lowered, watchlist_terms):
        steps = [
            AgentStep(
                role="analysis-sub-agent",
                task="Rank the bounded watchlist from core.db",
                inputs=["db/core.db"],
                commands=[
                    "uv run python -m app.skills hot --limit 10 --details",
                    "sqlite3 db/core.db '...bounded watchlist query...'",
                ],
                reason="Watchlists are mostly ranking and filtering work.",
            )
        ]
        if "hot" in lowered:
            steps.append(
                AgentStep(
                    role="hot-sub-agent",
                    task="Refresh or inspect the current hot signal",
                    inputs=["db/core.db", "sync.fetch_hot"],
                    commands=[
                        "python3 -m sync.fetch_hot",
                        "python3 -m sync.fetch_hot --vuln-id <CVE-ID> --simple",
                    ],
                    reason="Hot attention is a separate bounded query from the main watchlist ranking.",
                )
            )
        return RoutingPlan(
            request=normalized,
            mode="watchlist",
            primary_agent="main",
            confidence="high",
            summary="Use main to present the final short watchlist and sub-agents to gather ranking inputs.",
            sub_agents=steps,
            source_docs=["docs/DEEP_DIVE.md", "docs/FEEDS.md"],
        )

    if _has_any(lowered, feed_terms):
        return RoutingPlan(
            request=normalized,
            mode="feed_refresh",
            primary_agent="main",
            confidence="medium",
            summary="Use main for the user answer and a bounded worker for feed freshness or hot inspection.",
            sub_agents=[
                AgentStep(
                    role="maintenance-sub-agent",
                    task="Check feed freshness or refresh one bounded feed",
                    inputs=["db/core.db", "fetch_log"],
                    commands=[
                        "uv run python -m sync.feed_quality",
                        "uv run python -m sync.fetch_hot",
                    ],
                    reason="Feed freshness and hot attention can be checked independently.",
                )
            ],
            source_docs=["docs/FEEDS.md", "docs/DEEP_DIVE.md"],
        )

    return RoutingPlan(
        request=normalized,
        mode="general",
        primary_agent="main",
        confidence="low",
        summary="Keep the answer in main unless the task clearly benefits from bounded sub-agent evidence gathering.",
        sub_agents=[],
        source_docs=["docs/DEEP_DIVE.md"],
    )
