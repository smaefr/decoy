"""Parse attacker-supplied HTTP request fragments into structured fields."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import parse_qs

USERNAME_KEYS = ("username", "user", "login", "email", "userid", "user_name")
PASSWORD_KEYS = ("password", "pass", "passwd", "pwd")


@dataclass(frozen=True)
class ParsedRequest:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: str
    fields: dict[str, str]
    username: str | None
    password: str | None
    user_agent: str | None

    def combined_text(self) -> str:
        parts = [self.path, self.body, *(self.fields.values())]
        return "\n".join(part for part in parts if part)


def parse_headers(raw: Mapping[str, str] | None) -> dict[str, str]:
    if not raw:
        return {}
    return {str(key).lower(): str(value) for key, value in raw.items()}


def parse_query(path: str) -> tuple[str, dict[str, list[str]]]:
    if "?" not in path:
        return path, {}
    base, query_string = path.split("?", 1)
    return base, parse_qs(query_string, keep_blank_values=True)


def parse_body_fields(body: str, content_type: str | None) -> dict[str, str]:
    if not body:
        return {}
    ctype = (content_type or "").lower()
    if "json" in ctype:
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return {}
        if not isinstance(data, dict):
            return {}
        fields: dict[str, str] = {}
        for key, value in data.items():
            if value is None:
                fields[str(key)] = ""
            elif isinstance(value, (str, int, float, bool)):
                fields[str(key)] = str(value)
        return fields
    parsed = parse_qs(body, keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


def _first_field(fields: dict[str, str], keys: tuple[str, ...]) -> str | None:
    lowered = {key.lower(): value for key, value in fields.items()}
    for key in keys:
        if key in lowered:
            return lowered[key]
    return None


def parse_request(
    *,
    method: str = "GET",
    path: str = "/",
    headers: Mapping[str, str] | None = None,
    body: str | bytes | None = "",
) -> ParsedRequest:
    if isinstance(body, bytes):
        body_text = body.decode("utf-8", errors="replace")
    else:
        body_text = body or ""
    headers_l = parse_headers(headers)
    base_path, query = parse_query(path)
    query_fields = {key: values[-1] if values else "" for key, values in query.items()}
    body_fields = parse_body_fields(body_text, headers_l.get("content-type"))
    fields = {**query_fields, **body_fields}
    user_agent = headers_l.get("user-agent")
    return ParsedRequest(
        method=method.upper(),
        path=base_path,
        query=query,
        headers=headers_l,
        body=body_text,
        fields=fields,
        username=_first_field(fields, USERNAME_KEYS),
        password=_first_field(fields, PASSWORD_KEYS),
        user_agent=user_agent,
    )
