from __future__ import annotations

from decoy.parser import parse_request
from decoy.scorer import RateTracker, WEIGHTS, score_request, score_ssh_probe


def test_common_credentials_increase_score() -> None:
    parsed = parse_request(
        method="POST",
        path="/login",
        headers={"User-Agent": "Mozilla/5.0"},
        body="username=admin&password=password",
    )
    result = score_request(parsed)
    assert "common_username" in result.reasons
    assert "common_password" in result.reasons
    assert result.score >= WEIGHTS["common_username"] + WEIGHTS["common_password"]


def test_sql_metacharacters_and_traversal() -> None:
    parsed = parse_request(
        path="/files?path=../etc/hosts",
        headers={"User-Agent": "Mozilla/5.0"},
        body="q=' OR 1=1",
    )
    result = score_request(parsed)
    assert "sql_metacharacters" in result.reasons
    assert "path_traversal" in result.reasons


def test_scanner_user_agents() -> None:
    for marker in ("nikto", "sqlmap", "nmap", "masscan", "zgrab"):
        parsed = parse_request(path="/", headers={"User-Agent": f"scan/{marker}/1.0"})
        result = score_request(parsed)
        assert "scanner_user_agent" in result.reasons, marker


def test_missing_and_empty_user_agent() -> None:
    missing = score_request(parse_request(path="/"))
    assert "missing_user_agent" in missing.reasons
    empty = score_request(parse_request(path="/", headers={"User-Agent": "  "}))
    assert "missing_user_agent" in empty.reasons


def test_benign_request_scores_zero() -> None:
    parsed = parse_request(
        path="/login",
        headers={"User-Agent": "Mozilla/5.0"},
        body="username=unique_operator&password=uncommon-token",
    )
    result = score_request(parsed)
    assert result.score == 0
    assert result.reasons == []


def test_rate_tracker_threshold_and_expiry() -> None:
    tracker = RateTracker(window_sec=10.0, threshold=3)
    parsed = parse_request(path="/", headers={"User-Agent": "Mozilla/5.0"})
    first = score_request(parsed, src_ip="203.0.113.9", rate_tracker=tracker)
    assert "high_request_rate" not in first.reasons
    score_request(parsed, src_ip="203.0.113.9", rate_tracker=tracker)
    hot = score_request(parsed, src_ip="203.0.113.9", rate_tracker=tracker)
    assert "high_request_rate" in hot.reasons

    stale = RateTracker(window_sec=5.0, threshold=2)
    assert stale.hit("198.51.100.1", now=100.0) is False
    assert stale.hit("198.51.100.1", now=101.0) is True
    assert stale.hit("198.51.100.1", now=120.0) is False


def test_ssh_probe_scoring() -> None:
    empty = score_ssh_probe("")
    assert empty.reasons == ["ssh_probe"]
    noisy = score_ssh_probe("SSH-2.0-nmap_scan '../' union select")
    assert "ssh_probe" in noisy.reasons
    assert "scanner_user_agent" in noisy.reasons
    assert "sql_metacharacters" in noisy.reasons
    assert "path_traversal" in noisy.reasons
