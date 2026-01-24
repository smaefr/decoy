"""Defensive signature scoring for honeypot telemetry.

Matchers identify common probe tokens. They are detections only and are not
exploit instructions.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from decoy.parser import ParsedRequest

COMMON_USERNAMES = frozenset(
    {
        "admin",
        "administrator",
        "root",
        "test",
        "guest",
        "user",
        "oracle",
        "postgres",
        "mysql",
        "sa",
        "ftp",
        "pi",
        "ubuntu",
        "demo",
        "support",
        "operator",
    }
)

COMMON_PASSWORDS = frozenset(
    {
        "password",
        "password1",
        "123456",
        "12345678",
        "admin",
        "root",
        "pass",
        "toor",
        "changeme",
        "default",
        "letmein",
        "qwerty",
        "admin123",
        "passw0rd",
        "welcome",
        "test",
        "guest",
    }
)

SCANNER_UA_MARKERS = (
    "nikto",
    "sqlmap",
    "nmap",
    "masscan",
    "zgrab",
    "zgrab2",
)

SQL_TOKEN_RE = re.compile(
    r"(?:'|--|;|/\*|\*/|\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bor\b\s+1\s*=\s*1)",
    re.IGNORECASE,
)

TRAVERSAL_RE = re.compile(
    r"(?:\.\./|\.\.\\|%2e%2e(?:%2f|%5c|/|\\)|%252e%252e)",
    re.IGNORECASE,
)

WEIGHTS = {
    "common_username": 10,
    "common_password": 10,
    "sql_metacharacters": 25,
    "path_traversal": 20,
    "scanner_user_agent": 30,
    "missing_user_agent": 5,
    "high_request_rate": 15,
    "ssh_probe": 5,
}


@dataclass
class ScoreResult:
    score: int
    reasons: list[str] = field(default_factory=list)


class RateTracker:
    def __init__(self, window_sec: float = 60.0, threshold: int = 20) -> None:
        self.window_sec = window_sec
        self.threshold = threshold
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def hit(self, src_ip: str, now: float | None = None) -> bool:
        """Record a hit. Return True if this IP is at or over the threshold."""
        timestamp = time.monotonic() if now is None else now
        bucket = self._hits[src_ip]
        bucket.append(timestamp)
        cutoff = timestamp - self.window_sec
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return len(bucket) >= self.threshold


def _haystacks(parsed: ParsedRequest) -> list[str]:
    values = [parsed.path, parsed.body, parsed.username or "", parsed.password or ""]
    values.extend(parsed.fields.values())
    return values


def score_request(
    parsed: ParsedRequest,
    *,
    src_ip: str | None = None,
    rate_tracker: RateTracker | None = None,
) -> ScoreResult:
    reasons: list[str] = []
    score = 0

    if parsed.username and parsed.username.lower() in COMMON_USERNAMES:
        reasons.append("common_username")
        score += WEIGHTS["common_username"]

    if parsed.password and parsed.password.lower() in COMMON_PASSWORDS:
        reasons.append("common_password")
        score += WEIGHTS["common_password"]

    text = "\n".join(_haystacks(parsed))
    if SQL_TOKEN_RE.search(text):
        reasons.append("sql_metacharacters")
        score += WEIGHTS["sql_metacharacters"]
    if TRAVERSAL_RE.search(text):
        reasons.append("path_traversal")
        score += WEIGHTS["path_traversal"]

    user_agent = parsed.user_agent
    if user_agent is None or user_agent.strip() == "":
        reasons.append("missing_user_agent")
        score += WEIGHTS["missing_user_agent"]
    else:
        lowered = user_agent.lower()
        if any(marker in lowered for marker in SCANNER_UA_MARKERS):
            reasons.append("scanner_user_agent")
            score += WEIGHTS["scanner_user_agent"]

    if rate_tracker is not None and src_ip:
        if rate_tracker.hit(src_ip):
            reasons.append("high_request_rate")
            score += WEIGHTS["high_request_rate"]

    return ScoreResult(score=score, reasons=reasons)


def score_ssh_probe(client_data: str) -> ScoreResult:
    """Score a thin SSH identification exchange from whatever the client sent."""
    reasons = ["ssh_probe"]
    score = WEIGHTS["ssh_probe"]
    data = client_data or ""
    if SQL_TOKEN_RE.search(data):
        reasons.append("sql_metacharacters")
        score += WEIGHTS["sql_metacharacters"]
    if TRAVERSAL_RE.search(data):
        reasons.append("path_traversal")
        score += WEIGHTS["path_traversal"]
    lowered = data.lower()
    if any(marker in lowered for marker in SCANNER_UA_MARKERS):
        reasons.append("scanner_user_agent")
        score += WEIGHTS["scanner_user_agent"]
    return ScoreResult(score=score, reasons=reasons)
