"""Command-line interface for serving the decoy and querying telemetry."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from decoy.config import Config
from decoy.service import DecoyService
from decoy.store import Event, EventStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decoy",
        description="Automated honeypot: HTTP login decoy and SSH identification banner.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run HTTP and SSH listeners")
    serve.add_argument("--bind", default=None, help="Bind address")
    serve.add_argument("--http-port", type=int, default=None)
    serve.add_argument("--ssh-port", type=int, default=None)
    serve.add_argument("--db", default=None, help="SQLite database path")

    query = sub.add_parser("query", help="Query stored telemetry")
    query.add_argument("--min-score", type=int, default=0)
    query.add_argument("--proto", choices=("http", "ssh"), default=None)
    query.add_argument("--limit", type=int, default=100)
    query.add_argument("--db", default=None, help="SQLite database path")
    query.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _event_dict(event: Event) -> dict[str, object]:
    return {
        "id": event.id,
        "timestamp": event.timestamp,
        "src_ip": event.src_ip,
        "src_port": event.src_port,
        "proto": event.proto,
        "path": event.path,
        "score": event.score,
        "reasons": event.reasons,
        "payload_hash": event.payload_hash,
        "snippet": event.snippet,
    }


def cmd_serve(args: argparse.Namespace, config: Config) -> int:
    cfg = Config(
        bind=args.bind or config.bind,
        http_port=args.http_port if args.http_port is not None else config.http_port,
        ssh_port=args.ssh_port if args.ssh_port is not None else config.ssh_port,
        db_path=args.db or config.db_path,
        snippet_max=config.snippet_max,
        rate_window_sec=config.rate_window_sec,
        rate_threshold=config.rate_threshold,
        ssh_banner=config.ssh_banner,
        ssh_read_bytes=config.ssh_read_bytes,
        ssh_timeout_sec=config.ssh_timeout_sec,
    )
    service = DecoyService(cfg)
    print(
        f"decoy listening http://{cfg.bind}:{cfg.http_port} "
        f"ssh://{cfg.bind}:{cfg.ssh_port} db={cfg.db_path}",
        file=sys.stderr,
    )
    service.serve_forever()
    return 0


def cmd_query(args: argparse.Namespace, config: Config) -> int:
    db_path = args.db or config.db_path
    store = EventStore(db_path)
    events = store.query(min_score=args.min_score, proto=args.proto, limit=args.limit)
    if args.as_json:
        json.dump([_event_dict(event) for event in events], sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0
    if not events:
        print("no events")
        return 0
    header = f"{'id':>6} {'score':>5} {'proto':<5} {'src':<22} {'path':<24} reasons"
    print(header)
    print("-" * len(header))
    for event in events:
        src = f"{event.src_ip}:{event.src_port or 0}"
        path = (event.path or "")[:24]
        reasons = ",".join(event.reasons)
        print(f"{event.id or 0:>6} {event.score:>5} {event.proto:<5} {src:<22} {path:<24} {reasons}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = Config.from_env()
    if args.command == "serve":
        return cmd_serve(args, config)
    if args.command == "query":
        return cmd_query(args, config)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
