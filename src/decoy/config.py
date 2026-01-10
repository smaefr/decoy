from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return default if value is None or value == "" else value


@dataclass(frozen=True)
class Config:
    bind: str = "0.0.0.0"
    http_port: int = 8080
    ssh_port: int = 2222
    db_path: str = "decoy.db"
    snippet_max: int = 256
    rate_window_sec: float = 60.0
    rate_threshold: int = 20
    ssh_banner: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
    ssh_read_bytes: int = 4096
    ssh_timeout_sec: float = 5.0

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            bind=_env("DECOY_BIND", "0.0.0.0"),
            http_port=int(_env("DECOY_HTTP_PORT", "8080")),
            ssh_port=int(_env("DECOY_SSH_PORT", "2222")),
            db_path=_env("DECOY_DB", "decoy.db"),
            snippet_max=int(_env("DECOY_SNIPPET_MAX", "256")),
            rate_window_sec=float(_env("DECOY_RATE_WINDOW", "60")),
            rate_threshold=int(_env("DECOY_RATE_THRESHOLD", "20")),
            ssh_banner=_env("DECOY_SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"),
            ssh_read_bytes=int(_env("DECOY_SSH_READ_BYTES", "4096")),
            ssh_timeout_sec=float(_env("DECOY_SSH_TIMEOUT", "5")),
        )
