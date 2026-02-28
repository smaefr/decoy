from __future__ import annotations

import threading
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import pytest

from decoy.config import Config
from decoy.http_server import create_http_server
from decoy.scorer import RateTracker
from decoy.store import EventStore


@pytest.fixture
def http_server(store: EventStore, config: Config):
    rates = RateTracker(window_sec=config.rate_window_sec, threshold=config.rate_threshold)
    server = create_http_server(store, config, rates, bind="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, store
    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


def _url(server, path: str) -> str:
    host, port = server.server_address
    return f"http://{host}:{port}{path}"


def test_get_login_form_and_failed_post(http_server) -> None:
    server, store = http_server
    with urlopen(_url(server, "/"), timeout=2) as response:
        body = response.read().decode()
        assert response.status == 200
    assert 'name="username"' in body
    assert 'action="/login"' in body

    payload = urlencode({"username": "admin", "password": "password"}).encode()
    request = Request(
        _url(server, "/login"),
        data=payload,
        method="POST",
        headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"},
    )
    with urlopen(request, timeout=2) as response:
        page = response.read().decode()
        assert response.status == 200
    assert "Invalid username or password" in page

    deadline = time.time() + 2
    events = []
    while time.time() < deadline:
        events = store.query()
        if len(events) >= 2:
            break
        time.sleep(0.05)
    assert len(events) >= 2
    login_events = [event for event in events if event.path == "/login"]
    assert login_events
    assert "common_username" in login_events[0].reasons
    assert login_events[0].snippet is not None
    assert "password" not in (login_events[0].snippet or "") or "***" in (login_events[0].snippet or "")


def test_404_traversal_and_other_methods(http_server) -> None:
    server, store = http_server
    with pytest.raises(HTTPError) as err:
        urlopen(_url(server, "/files?path=../etc/passwd"), timeout=2)
    assert err.value.code == 404

    head = Request(_url(server, "/"), method="HEAD", headers={"User-Agent": ""})
    with urlopen(head, timeout=2) as response:
        assert response.status == 200

    put = Request(_url(server, "/login"), data=b"x=1", method="PUT", headers={"User-Agent": "sqlmap/1.0"})
    with pytest.raises(HTTPError) as put_err:
        urlopen(put, timeout=2)
    assert put_err.value.code == 405

    deadline = time.time() + 2
    events = []
    while time.time() < deadline:
        events = store.query()
        if len(events) >= 3:
            break
        time.sleep(0.05)
    paths = {event.path for event in events}
    assert any("etc/passwd" in (event.path or "") or "path_traversal" in event.reasons for event in events)
    assert "/" in paths
    scanners = [event for event in events if "scanner_user_agent" in event.reasons]
    assert scanners
