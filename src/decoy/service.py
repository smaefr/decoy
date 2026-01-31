"""Run HTTP and SSH decoy listeners together."""

from __future__ import annotations

import threading

from decoy.config import Config
from decoy.http_server import DecoyHTTPServer, create_http_server
from decoy.scorer import RateTracker
from decoy.ssh_banner import SSHBannerServer
from decoy.store import EventStore


class DecoyService:
    def __init__(self, config: Config, store: EventStore | None = None) -> None:
        self.config = config
        self.store = store or EventStore(config.db_path)
        self.rates = RateTracker(config.rate_window_sec, config.rate_threshold)
        self.http: DecoyHTTPServer | None = None
        self.ssh: SSHBannerServer | None = None
        self._http_thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def http_port(self) -> int:
        if self.http is None:
            return self.config.http_port
        return int(self.http.server_address[1])

    @property
    def ssh_port(self) -> int:
        if self.ssh is None:
            return self.config.ssh_port
        return self.ssh.port

    def start(self) -> None:
        self.http = create_http_server(self.store, self.config, self.rates)
        self.ssh = SSHBannerServer(self.store, self.config)
        self.ssh.start()
        self._http_thread = threading.Thread(
            target=self.http.serve_forever,
            name="decoy-http",
            daemon=True,
        )
        self._http_thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self.http is not None:
            self.http.shutdown()
            self.http.server_close()
            self.http = None
        if self.ssh is not None:
            self.ssh.stop()
            self.ssh = None
        if self._http_thread is not None:
            self._http_thread.join(timeout=2.0)
            self._http_thread = None

    def request_stop(self) -> None:
        self._stop.set()

    def serve_forever(self) -> None:
        self._stop.clear()
        self.start()
        try:
            while not self._stop.is_set():
                self._stop.wait(0.25)
        except KeyboardInterrupt:
            self._stop.set()
        finally:
            self.stop()
