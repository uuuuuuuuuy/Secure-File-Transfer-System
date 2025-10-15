"""Monitoring-oriented server web UI."""
from __future__ import annotations

import os
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, jsonify, render_template, request

CURRENT_DIR = Path(__file__).resolve().parent
PARENT_DIR = CURRENT_DIR.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.append(str(PARENT_DIR))

from database_handler import DatabaseHandler  # noqa: E402  pylint: disable=wrong-import-position
from files_handler import FilesHandler  # noqa: E402  pylint: disable=wrong-import-position


def _format_timestamp(value: Optional[str]) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            return value


def _infer_storage_root(clients: List[Dict[str, str]]) -> Path:
    # FilesHandler stores decrypted files relative to the process cwd.
    # Prefer existing client directories if available.
    candidates = []
    for client in clients:
        name = client.get("name")
        if not name:
            continue
        path = Path.cwd() / name
        if path.exists():
            candidates.append(path.parent)
    if candidates:
        return candidates[0]
    return Path.cwd()


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder=str(CURRENT_DIR / "templates"),
        static_folder=str(CURRENT_DIR / "static"),
    )
    app.config["SECRET_KEY"] = os.environ.get("WEBUI_SECRET_KEY", "server-webui-monitor")

    database_handler = DatabaseHandler()
    files_handler = FilesHandler()

    def serialize_overview():
        clients = database_handler.list_clients_overview()
        transfers = database_handler.list_recent_transfers()
        summary = database_handler.transfer_summary()
        for client in clients:
            client["last_seen_display"] = _format_timestamp(client.get("last_seen"))
            client["last_ip"] = client.get("last_ip") or "-"
            client["client_id"] = client.get("client_id") or "-"
        for item in transfers:
            item["received_at_display"] = _format_timestamp(item.get("received_at"))
            item["client_ip"] = item.get("client_ip") or "-"
        totals = {
            "clients": len(clients),
            "transfers": summary["transfers"],
            "verified": summary["verified"],
            "pending": summary["pending"],
        }
        return {
            "totals": totals,
            "clients": clients,
            "transfers": transfers,
        }

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.get("/api/overview")
    def get_overview():
        return jsonify(serialize_overview())

    @app.get("/files-browser")
    def files_browser():
        overview = serialize_overview()
        clients = overview["clients"]
        storage_root = _infer_storage_root(clients)
        listings = []
        for client in clients:
            name = client.get("name")
            if not name:
                continue
            client_dir = storage_root / name
            if not client_dir.exists() or not client_dir.is_dir():
                continue
            files = []
            for path in sorted(client_dir.iterdir()):
                if not path.is_file():
                    continue
                stat = path.stat()
                files.append(
                    {
                        "name": path.name,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "full_path": str(path),
                    }
                )
            listings.append(
                {
                    "client": name,
                    "directory": str(client_dir),
                    "files": files,
                }
            )
        return render_template("files_browser.html", listings=listings, storage_root=str(storage_root))

    @app.get("/api/server-info")
    def server_info():
        # Provide basic connection hints for operators.
        port = files_handler.get_port_number()
        hostnames = {socket.gethostname()}
        addresses = {"127.0.0.1"}
        try:
            addresses.add(socket.gethostbyname(socket.gethostname()))
        except socket.gaierror:
            pass
        try:
            hostname_ips = socket.getaddrinfo(socket.gethostname(), None)
            for _, _, _, _, sockaddr in hostname_ips:
                ip = sockaddr[0]
                if ip:
                    addresses.add(ip)
        except socket.gaierror:
            pass
        return jsonify(
            {
                "tcp_port": port,
                "http_port": os.environ.get("SERVER_WEBUI_PORT", "5000"),
                "hosts": sorted(addresses),
                "hostname": sorted(hostnames),
            }
        )

    @app.post("/api/transfers/<int:row_id>/verify")
    def verify_transfer(row_id: int):
        payload = request.get_json(silent=True) or {}
        verified = bool(payload.get("verified"))

        result = database_handler.set_transfer_verified(row_id, verified)
        if result is None:
            return jsonify({"error": "未找到对应的传输记录"}), 404

        message = "已标记为已确认" if verified else "已标记为待确认"
        response = {
            "message": message,
            "verified": verified,
            "transfer": result,
        }
        return jsonify(response)

    return app


def run():
    app = create_app()
    app.run(host="0.0.0.0", port=int(os.environ.get("SERVER_WEBUI_PORT", "5000")), debug=False)
