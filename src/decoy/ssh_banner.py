"""Thin SSH identification banner listener. Not an SSH implementation."""

from __future__ import annotations

import socket
import threading

from decoy.config import Config
from decoy.scorer import score_ssh_probe
from decoy.store import Event, EventStore, clip_snippet, hash_payload, utc_now


class SSHBannerServer:
    def __init__(
        self,
        store: EventStore,
        config: Config,
        bind: str | None = None,
        port: int | None = None,
    ) -> None:
        self.store = store
        self.config = config
        self.bind = bind if bind is not None else config.bind
        self.port = port if port is not None else config.ssh_port
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def actual_port(self) -> int:
        if self._sock is None:
            return self.port
        return int(self._sock.getsockname()[1])

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.bind, self.port))
        sock.listen(64)
        sock.settimeout(0.5)
        self._sock = sock
        self.port = self.actual_port
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="decoy-ssh", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _loop(self) -> None:
        sock = self._sock
        if sock is None:
            return
        while not self._stop.is_set():
            try:
                conn, addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            threading.Thread(
                target=self._handle,
                args=(conn, addr),
                name="decoy-ssh-conn",
                daemon=True,
            ).start()

    def _handle(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        src_ip, src_port = addr[0], int(addr[1])
        data = b""
        try:
            conn.settimeout(self.config.ssh_timeout_sec)
            banner = (self.config.ssh_banner + "\r\n").encode("ascii")
            conn.sendall(banner)
            try:
                data = conn.recv(self.config.ssh_read_bytes)
            except (TimeoutError, ConnectionError, OSError):
                data = b""
        finally:
            try:
                conn.close()
            except OSError:
                pass
        text = data.decode("utf-8", errors="replace")
        result = score_ssh_probe(text)
        snippet_src = text or "<empty>"
        self.store.insert(
            Event(
                timestamp=utc_now(),
                src_ip=src_ip,
                src_port=src_port,
                proto="ssh",
                path=None,
                score=result.score,
                reasons=result.reasons,
                payload_hash=hash_payload(snippet_src),
                snippet=clip_snippet(snippet_src, self.config.snippet_max),
            )
        )
