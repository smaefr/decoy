from __future__ import annotations

import socket
import time

from decoy.config import Config
from decoy.ssh_banner import SSHBannerServer
from decoy.store import EventStore


def test_ssh_banner_records_client_data(store: EventStore, config: Config) -> None:
    server = SSHBannerServer(store, config, bind="127.0.0.1", port=0)
    server.start()
    try:
        with socket.create_connection(("127.0.0.1", server.port), timeout=2) as sock:
            banner = b""
            while b"\n" not in banner:
                chunk = sock.recv(64)
                if not chunk:
                    break
                banner += chunk
            sock.sendall(b"SSH-2.0-nmap_OS_detection\r\n")
        assert banner.startswith(b"SSH-2.0-OpenSSH")
        deadline = time.time() + 2
        events = []
        while time.time() < deadline:
            events = store.query(proto="ssh")
            if events:
                break
            time.sleep(0.05)
        assert events
        event = events[0]
        assert event.proto == "ssh"
        assert "ssh_probe" in event.reasons
        assert "scanner_user_agent" in event.reasons
        assert event.payload_hash
    finally:
        server.stop()


def test_actual_port_before_start(store: EventStore, config: Config) -> None:
    server = SSHBannerServer(store, config, bind="127.0.0.1", port=2222)
    assert server.actual_port == 2222
    server._loop()


def test_ssh_recv_timeout_still_logged(store: EventStore, tmp_path) -> None:
    cfg = Config(
        bind="127.0.0.1",
        http_port=0,
        ssh_port=0,
        db_path=str(tmp_path / "timeout.db"),
        ssh_timeout_sec=0.05,
    )
    server = SSHBannerServer(store, cfg, bind="127.0.0.1", port=0)
    server.start()
    try:
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=2)
        sock.recv(128)
        time.sleep(0.2)
        sock.close()
        deadline = time.time() + 2
        events = []
        while time.time() < deadline:
            events = store.query(proto="ssh")
            if events:
                break
            time.sleep(0.05)
        assert events
    finally:
        server.stop()


def test_ssh_empty_client_still_logged(store: EventStore, config: Config) -> None:
    server = SSHBannerServer(store, config, bind="127.0.0.1", port=0)
    server.start()
    try:
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=2)
        sock.recv(128)
        sock.close()
        deadline = time.time() + 2
        events = []
        while time.time() < deadline:
            events = store.query(proto="ssh")
            if events:
                break
            time.sleep(0.05)
        assert events
        assert events[0].snippet == "<empty>" or events[0].snippet
    finally:
        server.stop()
