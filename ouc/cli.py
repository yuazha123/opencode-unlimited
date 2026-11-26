"""Unified command-line entry point.

Commands cover hopping, lane setup, health checks, keepers, a dashboard, and
archive editing.  No command registers a service, edits a firewall, or runs a
remote installer.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import auto_resume, common, desktop_brand, proxy_chain, workers, zen_proxy


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ouc", description="Opencode Unlimited")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="print local health information")

    hop = sub.add_parser("hop", help="show the next egress rotation action")
    hop.add_argument("--commit", action="store_true", help="advance the proxy ring index")

    lane = sub.add_parser("lane", help="print the environment for a launched client")
    lane.add_argument("--port", type=int, default=0)

    sub.add_parser("guard", help="run one wall-detection tick")

    keeper = sub.add_parser("keeper", help="run one keeper tick")
    keeper.add_argument("--connected", action="store_true", default=True)

    watchdog = sub.add_parser("watchdog", help="check worker heartbeats")
    watchdog.add_argument("--worker", choices=["keeper", "guard"], default="guard")

    dash = sub.add_parser("dashboard", help="serve the local JSON dashboard")
    dash.add_argument("--port", type=int, default=0)
    dash.add_argument("--once", action="store_true", help="print URL and exit")

    brand = sub.add_parser("desktop-brand", help="dry-run by default; --apply requires explicit consent")
    brand.add_argument("action", choices=["status", "apply", "restore"])
    brand.add_argument("--install", default="")
    brand.add_argument("--apply", action="store_true", help="apply the change to the archive")

    resume = sub.add_parser("resume", help="opt-in session resume helper")
    resume.add_argument("--enable", choices=["on", "off"])

    config = sub.add_parser("config", help="read or write egress configuration")
    config.add_argument("action", choices=["show", "set"])
    config.add_argument("--mode", choices=["warp", "tor", "custom", "clean"], default="warp")
    config.add_argument("--proxy", default="127.0.0.1:10808")
    config.add_argument("--type", default="socks5")
    config.add_argument("--scope", default="")

    sub.add_parser("parse-proxy", help="parse a proxy string")
    return parser


def brand_install_path(raw: str) -> Path:
    return Path(raw) if raw else (common.LOCAL_APPDATA / "Programs" / "ai.opencode.desktop")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "doctor":
        print(json.dumps({
            "data_root": str(common.DEST_DIR),
            "egress": proxy_chain.get_egress_config(),
            "proxy": zen_proxy.proxy_status(),
            "guard_heartbeat_age": common.heartbeat_age(workers.GUARD_HEARTBEAT),
            "keeper_heartbeat_age": common.heartbeat_age(workers.KEEPER_HEARTBEAT),
            "auto_resume": auto_resume.is_auto_resume_enabled(),
            "note": "This tool never installs services, sudoers rules, or firewall rules.",
        }, indent=2))
        return 0

    if args.command == "hop":
        if args.commit:
            index = proxy_chain.advance_custom_proxy()
            print(f"advanced custom proxy ring to {index}")
        else:
            spec = proxy_chain.current_spec()
            print(f"mode={proxy_chain.get_egress_config().get('mode')} next={spec['raw'] if spec else 'n/a'}")
        return 0

    if args.command == "lane":
        server, port = zen_proxy.start_proxy_server("127.0.0.1", args.port)
        url = f"http://127.0.0.1:{port}"
        print(f"HTTP_PROXY={url}\nHTTPS_PROXY={url}\nALL_PROXY={url}")
        print("# Press Ctrl+C to stop the loopback proxy.", file=sys.stderr)
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            zen_proxy.stop_proxy(server)
        return 0

    if args.command == "guard":
        state = workers.load_state()
        try:
            text = common.OPENCODE_LOG_FILE.read_text(encoding="utf-8", errors="replace") if common.OPENCODE_LOG_FILE.is_file() else ""
        except OSError:
            text = ""
        print(json.dumps(workers.guard_tick(log_text=text, state=state), indent=2))
        return 0

    if args.command == "keeper":
        print(json.dumps(workers.keeper_tick(connected=args.connected), indent=2))
        return 0

    if args.command == "watchdog":
        print(workers.watchdog_check(args.worker))
        return 0

    if args.command == "dashboard":
        from . import dashboard

        server, port = dashboard.serve("127.0.0.1", args.port)
        print(f"http://127.0.0.1:{port}/")
        if args.once:
            server.shutdown()
            server.server_close()
            return 0
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            server.shutdown()
            server.server_close()
        return 0

    if args.command == "desktop-brand":
        archive = brand_install_path(args.install) / desktop_brand.ASAR_RELATIVE
        if args.action == "status":
            print(json.dumps(desktop_brand.status(archive), indent=2))
        elif args.action == "apply":
            print(json.dumps(desktop_brand.apply(archive, apply_change=args.apply), indent=2))
        else:
            print(json.dumps(desktop_brand.restore(archive), indent=2))
        return 0

    if args.command == "resume":
        if args.enable:
            auto_resume.set_auto_resume(args.enable == "on")
        print(f"auto_resume={auto_resume.is_auto_resume_enabled()}")
        return 0

    if args.command == "config":
        if args.action == "show":
            print(json.dumps(proxy_chain.get_egress_config(), indent=2))
        else:
            print(json.dumps(proxy_chain.set_egress_config(args.mode, args.proxy, args.type, args.scope), indent=2))
        return 0

    if args.command == "parse-proxy":
        print(json.dumps(proxy_chain.parse_proxy_specs(sys.stdin.read()), indent=2))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
