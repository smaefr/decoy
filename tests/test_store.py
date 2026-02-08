from __future__ import annotations

from decoy.store import Event, EventStore, clip_snippet, hash_payload, redact_snippet, utc_now


def test_insert_and_query_filters(store: EventStore) -> None:
    now = utc_now()
    low = Event(
        timestamp=now,
        src_ip="192.0.2.1",
        src_port=1111,
        proto="http",
        path="/",
        score=5,
        reasons=["missing_user_agent"],
        payload_hash=hash_payload("a"),
        snippet="a",
    )
    high = Event(
        timestamp=now,
        src_ip="192.0.2.2",
        src_port=2222,
        proto="ssh",
        path=None,
        score=40,
        reasons=["ssh_probe", "scanner_user_agent"],
        payload_hash=hash_payload("b"),
        snippet="b",
    )
    assert store.insert(low) == 1
    assert store.insert(high) == 2
    assert len(store.query()) == 2
    only_high = store.query(min_score=20)
    assert len(only_high) == 1
    assert only_high[0].proto == "ssh"
    http_only = store.query(proto="HTTP")
    assert len(http_only) == 1
    assert http_only[0].path == "/"
    limited = store.query(limit=1)
    assert len(limited) == 1


def test_snippet_helpers() -> None:
    assert clip_snippet("short", 256) == "short"
    clipped = clip_snippet("abcdefghij", 8)
    assert clipped.endswith("...")
    assert len(clipped) == 8
    assert clip_snippet("abcd", 2) == "ab"
    redacted = redact_snippet("password=hunter2 extra", "hunter2", 256)
    assert "hunter2" not in redacted
    assert "***" in redacted
    short_pw = redact_snippet("pw=ab", "ab", 256)
    assert "ab" in short_pw
    assert hash_payload("x") == hash_payload("x")
    assert hash_payload("x") != hash_payload("y")


def test_creates_parent_directory(tmp_path) -> None:
    nested = tmp_path / "data" / "nested" / "events.db"
    store = EventStore(nested)
    event_id = store.insert(
        Event(
            timestamp=utc_now(),
            src_ip="127.0.0.1",
            src_port=1,
            proto="http",
            path="/",
            score=0,
            reasons=[],
            payload_hash="abc",
            snippet="",
        )
    )
    assert event_id == 1
    assert nested.exists()
