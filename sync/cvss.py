"""Identify comparable source assessments and calculate vector-only base scores."""
from functools import lru_cache
import re


def assessment(value):
    """Usable by the dependency-free feed jobs as well as the mart."""
    score = value.get("cvss_score")
    vector = value.get("cvss_vector") or ""
    match = re.match(r"CVSS:(\d+\.\d+)/", vector) if isinstance(vector, str) else None
    version = match[1] if match else "unknown"
    if isinstance(vector, str) and vector.startswith("AV:"):
        version = "2.0"
    if type(score) in (int, float) and 0 <= score <= 10:
        measurement = score
    elif version != "unknown" and vector:
        measurement = vector
    else:
        return None
    return measurement, str(value.get("ghsa_id") or ""), version


@lru_cache(maxsize=4096)
def base_score(vector, version):
    from cvss import CVSS2, CVSS3, CVSS4, CVSSError
    from cvss.constants4 import METRICS_MANDATORY

    try:
        if version == "2.0":
            return CVSS2(vector.removeprefix("CVSS:2.0/")).scores()[0]
        if version in ("3.0", "3.1"):
            return CVSS3(vector).scores()[0]
        if version == "4.0":
            parsed = CVSS4(vector)
            metrics = "/".join(f"{key}:{parsed.metrics[key]}" for key in METRICS_MANDATORY)
            return CVSS4("CVSS:4.0/" + metrics).scores()[0]
    except CVSSError:
        return None
    return None


def rating(value):
    series = assessment(value)
    if series is None:
        return None
    score, advisory, version = series
    if isinstance(score, str):
        score = base_score(score, version)
    return (score, advisory, version) if score is not None else None
