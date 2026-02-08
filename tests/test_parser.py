from __future__ import annotations

from decoy.parser import parse_body_fields, parse_headers, parse_query, parse_request


def test_parse_form_urlencoded_extracts_credentials() -> None:
    parsed = parse_request(
        method="post",
        path="/login",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=b"username=alice&password=secret",
    )
    assert parsed.method == "POST"
    assert parsed.username == "alice"
    assert parsed.password == "secret"
    assert parsed.fields["username"] == "alice"


def test_parse_json_body() -> None:
    parsed = parse_request(
        method="POST",
        path="/login",
        headers={"Content-Type": "application/json"},
        body='{"user":"bob","pass":true}',
    )
    assert parsed.username == "bob"
    assert parsed.password == "True"


def test_parse_json_null_and_invalid() -> None:
    invalid = parse_request(
        method="POST",
        path="/login",
        headers={"Content-Type": "application/json"},
        body="{not-json",
    )
    assert invalid.fields == {}
    listed = parse_body_fields("[1,2]", "application/json")
    assert listed == {}
    nulls = parse_body_fields('{"login":null}', "application/json")
    assert nulls["login"] == ""


def test_parse_query_string_credentials() -> None:
    parsed = parse_request(path="/login?email=ops@example.test&pwd=")
    assert parsed.path == "/login"
    assert parsed.username == "ops@example.test"
    assert parsed.password == ""


def test_parse_headers_empty_and_query_without_qmark() -> None:
    assert parse_headers(None) == {}
    assert parse_query("/only") == ("/only", {})


def test_bytes_body_and_combined_text() -> None:
    parsed = parse_request(path="/x", body=b"a=1")
    assert "a=1" in parsed.combined_text()
    empty = parse_request(path="/", body=None)
    assert empty.body == ""
