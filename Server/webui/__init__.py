"""Monitoring-oriented server web UI."""
from __future__ import annotations

import base64
import binascii
import os
import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, jsonify, render_template, request, session

CURRENT_DIR = Path(__file__).resolve().parent
PARENT_DIR = CURRENT_DIR.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.append(str(PARENT_DIR))

from database_handler import DatabaseHandler  # noqa: E402  pylint: disable=wrong-import-position
from encryption_handler import EncryptionHandler  # noqa: E402  pylint: disable=wrong-import-position
from files_handler import FilesHandler  # noqa: E402  pylint: disable=wrong-import-position
from verification import (  # noqa: E402  pylint: disable=wrong-import-position
    is_valid_client_id,
    is_valid_client_name,
)


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
    encryption_handler = EncryptionHandler()
    files_handler = FilesHandler()

    def _session_client_id_bytes() -> Optional[bytes]:
        client_id = session.get("client_id")
        if not client_id:
            return None
        try:
            return bytes.fromhex(client_id)
        except (TypeError, ValueError):
            try:
                return DatabaseHandler._normalize_client_id(client_id)  # type: ignore[attr-defined]
            except Exception:  # pylint: disable=broad-except
                return None

    def _store_aes_key_in_session(client_name: str) -> Optional[str]:
        aes_key = database_handler.get_AES_key(client_name)
        if aes_key is None:
            return None
        if isinstance(aes_key, bytes):
            aes_key = aes_key.decode()
        session["aes_key"] = aes_key
        return aes_key

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

    @app.get("/api/session")
    def get_session_state():
        client_id = session.get("client_id")
        client_name = session.get("client_name")
        has_aes = "aes_key" in session
        return jsonify(
            {
                "clientId": client_id,
                "clientName": client_name,
                "hasAesKey": has_aes,
            }
        )

    @app.get("/api/overview")
    def get_overview():
        return jsonify(serialize_overview())

    @app.post("/api/register")
    def register_client():
        payload = request.get_json(silent=True) or {}
        client_name = str(payload.get("clientName", "")).strip()

        if not client_name:
            return jsonify({"error": "缺少客户端名称"}), 400

        if not is_valid_client_name(client_name):
            return jsonify({"error": "客户端名称仅支持字母、数字与空格"}), 400

        if database_handler.is_client_exists(client_name):
            return jsonify({"error": "客户端名称已存在"}), 409

        client_id_bytes = database_handler.register_client(client_name)
        client_id_hex = client_id_bytes.hex()

        session.clear()
        session["client_name"] = client_name
        session["client_id"] = client_id_hex

        return (
            jsonify(
                {
                    "clientId": client_id_hex,
                    "clientName": client_name,
                    "message": "注册成功，请继续上传公钥。",
                }
            ),
            201,
        )

    @app.post("/api/login")
    def login_client():
        payload = request.get_json(silent=True) or {}
        client_name = str(payload.get("clientName", "")).strip()
        client_id = str(payload.get("clientId", "")).strip().lower()

        if not client_name or not client_id:
            return jsonify({"error": "缺少客户端名称或客户端 ID"}), 400

        if not is_valid_client_name(client_name):
            return jsonify({"error": "客户端名称仅支持字母、数字与空格"}), 400

        if not is_valid_client_id(client_id):
            return jsonify({"error": "客户端 ID 非法"}), 400

        if not database_handler.does_client_match_id(client_name, client_id):
            return jsonify({"error": "未找到匹配的客户端"}), 404

        if not database_handler.is_RSA_key_exists(client_name):
            return jsonify({"error": "该客户端尚未上传公钥，请先执行密钥交换。"}), 409

        encryption_handler.generate_AES_key(client_name)
        encrypted_aes = encryption_handler.get_encrypted_AES_key(client_name)
        aes_key = _store_aes_key_in_session(client_name)

        session["client_name"] = client_name
        session["client_id"] = client_id

        client_id_bytes = _session_client_id_bytes()
        if client_id_bytes:
            database_handler.update_last_seen(client_id_bytes, request.remote_addr)

        return jsonify(
            {
                "clientId": client_id,
                "clientName": client_name,
                "encryptedAESKey": encrypted_aes,
                "hasAesKey": aes_key is not None,
                "message": "已生成新的 AES 密钥。",
            }
        )

    @app.post("/api/key-exchange")
    def key_exchange():
        if "client_name" not in session:
            return jsonify({"error": "请先注册或登录客户端"}), 401

        payload = request.get_json(silent=True) or {}
        public_key = str(payload.get("publicKey", "")).strip()

        if not public_key:
            return jsonify({"error": "缺少公钥"}), 400

        client_name = session["client_name"]
        database_handler.update_public_RSA_key(client_name, public_key)
        encryption_handler.generate_AES_key(client_name)
        encrypted_aes = encryption_handler.get_encrypted_AES_key(client_name)
        aes_key = _store_aes_key_in_session(client_name)

        client_id_bytes = _session_client_id_bytes()
        if client_id_bytes:
            database_handler.update_last_seen(client_id_bytes, request.remote_addr)

        return jsonify(
            {
                "clientId": session.get("client_id"),
                "encryptedAESKey": encrypted_aes,
                "hasAesKey": aes_key is not None,
                "message": "AES 密钥已下发，请使用私钥解密。",
            }
        )

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

    @app.post("/api/upload")
    def upload_file():
        if "client_name" not in session or "aes_key" not in session:
            return jsonify({"error": "请先完成注册及密钥交换"}), 401

        payload = request.get_json(silent=True) or {}
        file_name = str(payload.get("fileName", "")).strip()
        encrypted_payload = payload.get("payload")
        file_size = payload.get("plainSize")

        if not file_name or not encrypted_payload:
            return jsonify({"error": "缺少文件或文件名"}), 400

        if file_size is None:
            return jsonify({"error": "缺少文件大小"}), 400

        try:
            file_size = int(file_size)
        except (TypeError, ValueError):
            return jsonify({"error": "文件大小格式不正确"}), 400

        try:
            encrypted_bytes = base64.b64decode(encrypted_payload)
        except (binascii.Error, ValueError):
            return jsonify({"error": "加密文件内容不是有效的 Base64"}), 400

        aes_key = session["aes_key"]
        decrypted_content = encryption_handler.decrypt_file(encrypted_bytes, aes_key, file_name)
        saved_path = files_handler.save_decrypted_file(session["client_name"], file_name, decrypted_content)

        client_id_bytes = _session_client_id_bytes()
        client_ip = request.remote_addr
        database_handler.update_file_info(
            client_id_bytes,
            session["client_name"],
            file_name,
            client_ip=client_ip,
        )
        database_handler.update_crc(client_id_bytes, False)
        crc_value = encryption_handler.calculate_crc(session["client_name"], file_name)
        if client_id_bytes:
            database_handler.update_last_seen(client_id_bytes, client_ip)

        return jsonify(
            {
                "crc": crc_value,
                "message": "文件上传并保存成功，请确认 CRC。",
                "fileSize": file_size,
                "savedPath": saved_path,
            }
        )

    @app.post("/api/files/ack")
    def acknowledge_crc():
        if "client_name" not in session:
            return jsonify({"error": "请先注册或登录客户端"}), 401

        payload = request.get_json(silent=True) or {}
        verified_value = payload.get("verified")

        if isinstance(verified_value, str):
            verified = verified_value.lower() in {"true", "1", "yes", "valid"}
        else:
            verified = bool(verified_value)

        client_id_bytes = _session_client_id_bytes()
        database_handler.update_crc(client_id_bytes, verified)
        if client_id_bytes:
            database_handler.update_last_seen(client_id_bytes, request.remote_addr)

        return jsonify(
            {
                "verified": verified,
                "message": "CRC 状态已更新。",
            }
        )

    @app.get("/api/files")
    def list_files():
        if "client_name" not in session:
            return jsonify({"files": []})

        client_id_bytes = _session_client_id_bytes()
        files = database_handler.list_files_for_client(client_id_bytes)
        return jsonify({"files": files})

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
