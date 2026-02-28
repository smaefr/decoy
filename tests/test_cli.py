from __future__ import annotations

import json
import threading
import time
from urllib.request import urlopen

import pytest

import runpy

from decoy import __version__
from decoy.cli import build_parser, main
from decoy.config import Config
from decoy.service import DecoyService
from decoy.store import Event, EventStore, utc_now


def test_version_and_parser_help() -> None:
    assert __version__
    parser = build_parser()
    args = parser.parse_args(["query", "--min-score", "10", "--proto", "http"])
    assert args.command == "query"
    assert args.min_score == 10


def test_query_table_and_json(store: EventStore, db_path: str, capsys: pytest.CaptureFixture[str]) -> None:
    empty_code = main(["query", "--db", db_path])
    assert empty_code == 0
    assert "no events" in capsys.readouterr().out

    store.insert(
        Event(
            timestamp=utc_now(),
            src_ip="192.0.2.8",
            src_port=4444,
            proto="http",
            path="/login",
            score=20,
            reasons=["common_username"],
            payload_hash="deadbeef",
            snippet="POST /login",
        )
    )
    table_code = main(["query", "--db", db_path, "--min-score", "5", "--proto", "http"])
    assert table_code == 0
    table = capsys.readouterr().out
    assert "common_username" in table
    assert "/login" in table

    json_code = main(["query", "--db", db_path, "--json"])
    assert json_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["score"] == 20


def test_main_requires_command() -> None:
    with pytest.raises(SystemExit):
        main([])


def test_module_entrypoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["decoy", "query", "--help"])
    with pytest.raises(SystemExit) as err:
        runpy.run_module("decoy", run_name="__main__")
    assert err.value.code == 0


def test_config_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECOY_BIND", "127.0.0.1")
    monkeypatch.setenv("DECOY_HTTP_PORT", "8099")
    monkeypatch.setenv("DECOY_SSH_PORT", "2299")
    monkeypatch.setenv("DECOY_DB", "/tmp/decoy-test.db")
    monkeypatch.setenv("DECOY_SNIPPET_MAX", "64")
    monkeypatch.setenv("DECOY_RATE_WINDOW", "30")
    monkeypatch.setenv("DECOY_RATE_THRESHOLD", "9")
    cfg = Config.from_env()
    assert cfg.bind == "127.0.0.1"
    assert cfg.http_port == 8099
    assert cfg.ssh_port == 2299
    assert cfg.db_path == "/tmp/decoy-test.db"
    assert cfg.snippet_max == 64
    assert cfg.rate_window_sec == 30.0
    assert cfg.rate_threshold == 9


def test_service_start_stop_and_serve_forever(config: Config) -> None:
    service = DecoyService(config)
    service.start()
    try:
        assert service.http_port > 0
        assert service.ssh_port > 0
        with urlopen(f"http://127.0.0.1:{service.http_port}/index.html", timeout=2) as response:
            assert response.status == 200
    finally:
        service.stop()
    assert service.http is None

    idle = DecoyService(config)
    assert idle.http_port == config.http_port
    assert idle.ssh_port == config.ssh_port

    runner = DecoyService(config)
    thread = threading.Thread(target=runner.serve_forever, daemon=True)
    thread.start()
    deadline = time.time() + 2
    while time.time() < deadline and runner.http is None:
        time.sleep(0.05)
    runner.request_stop()
    thread.join(timeout=3.0)
    assert not thread.is_alive()


def test_serve_forever_handles_keyboard_interrupt(config: Config) -> None:
    service = DecoyService(config)
    started = {"n": 0}
    stopped = {"n": 0}

    def fake_start() -> None:
        started["n"] += 1

    def fake_stop() -> None:
        stopped["n"] += 1

    def boom(_timeout: float | None = None) -> bool:
        raise KeyboardInterrupt()

    service.start = fake_start  # type: ignore[method-assign]
    service.stop = fake_stop  # type: ignore[method-assign]
    service._stop.wait = boom  # type: ignore[method-assign]
    service.serve_forever()
    assert started["n"] == 1
    assert stopped["n"] == 1


def test_cmd_serve_uses_flags(monkeypatch: pytest.MonkeyPatch, config: Config, capsys: pytest.CaptureFixture[str]) -> None:
    started = {}

    class FakeService:
        def __init__(self, cfg: Config) -> None:
            started["cfg"] = cfg

        def serve_forever(self) -> None:
            started["ran"] = True

    monkeypatch.setattr("decoy.cli.DecoyService", FakeService)
    monkeypatch.setattr("decoy.cli.Config.from_env", lambda: config)
    code = main(
        [
            "serve",
            "--bind",
            "127.0.0.1",
            "--http-port",
            "8081",
            "--ssh-port",
            "2223",
            "--db",
            config.db_path,
        ]
    )
    assert code == 0
    assert started["ran"] is True
    assert started["cfg"].http_port == 8081
    assert started["cfg"].ssh_port == 2223
    err = capsys.readouterr().err
    assert "listening" in err
