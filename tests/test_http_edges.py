from __future__ import annotations

from io import BytesIO

from decoy.config import Config
from decoy.http_server import make_handler
from decoy.scorer import RateTracker
from decoy.store import EventStore


class _DummyServer:
    def __init__(self) -> None:
        self.base_path = "/"


def test_invalid_content_length_reads_empty_body(store: EventStore, config: Config) -> None:
    handler_cls = make_handler(store, config, RateTracker())
    handler = handler_cls.__new__(handler_cls)
    handler.headers = {"Content-Length": "nope"}
    handler.rfile = BytesIO(b"ignored")
    assert handler._read_body() == b""

    handler.headers = {"Content-Length": "0"}
    assert handler._read_body() == b""
