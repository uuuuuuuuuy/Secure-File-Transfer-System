"""Client-side web UI for managing registration, key exchange and file sending."""
from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from .config import (
    DEFAULT_BIND_PORT,
    DEFAULT_REMOTE_HTTP_PORT,
    TransferFile,
    get_base_dir,
    resolve_remote_base,
)
from .key_manager import KeyManager
from .remote_client import RemoteClient, RemoteClientError
from .state_store import StateStore


def create_app() -> Flask:
    base_dir = get_base_dir()
    transfer_file = TransferFile(base_dir)
    key_manager = KeyManager(base_dir)
    state_store = StateStore(base_dir)

    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    app.config["SECRET_KEY"] = os.environ.get("CLIENT_WEBUI_SECRET_KEY", "client-webui-dev")
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB for local uploads

    remote_client: Optional[RemoteClient] = None

    def get_remote_client() -> RemoteClient:
        nonlocal remote_client
        info = transfer_file.read()
        base_url = resolve_remote_base(info)
        if remote_client is None or remote_client.base_url != base_url:
            remote_client = RemoteClient(base_url)
        return remote_client

    def encrypt_file_for_upload(path: Path, aes_key_b64: str) -> Tuple[str, int]:
        raw = path.read_bytes()
        key = base64.b64decode(aes_key_b64)
        if len(key) not in {16, 24, 32}:
            raise ValueError("服务器返回的 AES 密钥长度异常")
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(raw) + padder.finalize()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        payload = base64.b64encode(iv + ciphertext).decode("ascii")
        return payload, len(raw)

    def perform_send(file_path: Path, client: RemoteClient) -> Dict[str, Any]:
        aes_key = state_store.get_aes_key()
        if not aes_key:
            raise ValueError("尚未保存 AES 会话密钥，请先完成登录或密钥交换。")

        encrypted_payload, plain_size = encrypt_file_for_upload(file_path, aes_key)
        server_response = client.upload_file(file_path.name, encrypted_payload, plain_size)
        state_store.record_send(file_path.name)
        return server_response

    def serialize_state():
        transfer_info = None
        try:
            transfer_info = transfer_file.read()
        except Exception:
            transfer_info = None

        me_info = key_manager.read_me_info()
        state = state_store.status()

        return {
            "serverEndpoint": transfer_info.server_tcp_endpoint if transfer_info else None,
            "serverHost": transfer_info.server_host if transfer_info else None,
            "serverTcpPort": transfer_info.server_tcp_port if transfer_info else None,
            "serverHttpPort": transfer_info.server_http_port_or_default()
            if transfer_info
            else DEFAULT_REMOTE_HTTP_PORT,
            "serverHttpPortConfigured": transfer_info.server_http_port if transfer_info else None,
            "serverHttpEndpoint": transfer_info.server_http_endpoint() if transfer_info else None,
            "clientName": transfer_info.client_name if transfer_info else me_info.client_name,
            "clientId": me_info.client_id,
            "filePath": transfer_info.file_path if transfer_info else None,
            "registered": bool(me_info.client_id),
            "hasAesKey": bool(state.get("has_aes_key")),
            "lastKeyExchange": state.get("last_key_exchange"),
            "lastSendAt": state.get("last_send"),
            "lastSendFile": state.get("last_send_file"),
            "publicKeyFingerprint": key_manager.public_key_fingerprint(),
            "publicKeyCreatedAt": key_manager.public_key_created_at(),
        }

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.get("/api/state")
    def get_state():
        return jsonify(serialize_state())

    @app.post("/api/server")
    def update_server():
        payload = request.get_json(silent=True) or {}
        server_host = str(payload.get("serverHost", "")).strip()
        if not server_host:
            return jsonify({"error": "请输入服务器 IP 或域名"}), 400

        try:
            server_tcp_port = int(payload.get("serverTcpPort"))
        except (TypeError, ValueError):
            return jsonify({"error": "TCP 端口格式不正确"}), 400

        if not 1 <= server_tcp_port <= 65535:
            return jsonify({"error": "TCP 端口号应在 1-65535 之间"}), 400

        http_port_provided = "serverHttpPort" in payload
        http_port_raw = payload.get("serverHttpPort")
        http_port: Optional[int]
        if http_port_raw in (None, "", "default"):
            http_port = None
        else:
            try:
                http_port = int(http_port_raw)
            except (TypeError, ValueError):
                return jsonify({"error": "HTTP 接口端口格式不正确"}), 400
            if not 1 <= http_port <= 65535:
                return jsonify({"error": "HTTP 接口端口号应在 1-65535 之间"}), 400

        existing_name = None
        existing_file = None
        existing_http_port = None
        if transfer_file.exists():
            try:
                info = transfer_file.read()
                existing_name = info.client_name
                existing_file = info.file_path
                existing_http_port = info.server_http_port
            except Exception:
                existing_name = None
                existing_file = None
                existing_http_port = None

        if http_port_provided:
            http_port_to_save = http_port
        else:
            http_port_to_save = existing_http_port

        try:
            transfer_file.write(
                server_host,
                server_tcp_port,
                client_name=existing_name,
                file_path=existing_file,
                server_http_port=http_port_to_save,
            )
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"写入 transfer.info 失败: {exc}"}), 500

        nonlocal remote_client
        remote_client = None

        response = serialize_state()
        response.update(
            {
                "message": "服务器配置已更新",
            }
        )
        return jsonify(response)

    @app.post("/api/register")
    def register():
        if not transfer_file.exists():
            return jsonify({"error": "找不到 transfer.info，请先配置客户端。"}), 400

        payload = request.get_json(silent=True) or {}
        client_name = str(payload.get("clientName", "")).strip()
        if not client_name:
            return jsonify({"error": "请输入客户端名称"}), 400

        try:
            client = get_remote_client()
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"读取服务器配置失败: {exc}"}), 500

        try:
            data = client.register(client_name)
        except RemoteClientError as exc:
            return jsonify({"error": str(exc)}), 502

        client_id = data.get("clientId")
        if not client_id:
            return jsonify({"error": "服务器未返回客户端 ID"}), 502

        transfer_file.update(client_name=client_name)
        key_manager.rotate_keys(client_name, client_id)
        state_store.clear()

        response = serialize_state()
        response.update(
            {
                "clientId": client_id,
                "publicKeyFingerprint": key_manager.public_key_fingerprint(),
                "publicKeyCreatedAt": key_manager.public_key_created_at(),
                "message": data.get("message", "注册成功"),
            }
        )
        return jsonify(response), 201

    @app.post("/api/login")
    def login():
        if not transfer_file.exists():
            return jsonify({"error": "找不到 transfer.info，请先配置客户端。"}), 400

        payload = request.get_json(silent=True) or {}
        client_name = str(payload.get("clientName", "")).strip()
        client_id = str(payload.get("clientId", "")).strip()
        if not client_name or not client_id:
            return jsonify({"error": "请输入客户端名称与 ID"}), 400

        try:
            client = get_remote_client()
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"读取服务器配置失败: {exc}"}), 500

        transfer_file.update(client_name=client_name)
        key_manager.ensure_keys(client_name, client_id)

        try:
            data = client.login(client_name, client_id)
        except RemoteClientError as exc:
            return jsonify({"error": str(exc)}), 502

        encrypted_aes = data.get("encryptedAESKey")
        if encrypted_aes:
            try:
                aes_key = key_manager.decrypt_aes_key(encrypted_aes)
                state_store.record_aes_key(aes_key)
            except Exception as exc:  # pylint: disable=broad-except
                return jsonify({"error": f"解密服务器返回的 AES 密钥失败: {exc}"}), 500

        response = serialize_state()
        response.update(
            {
                "message": data.get("message", "登录成功"),
                "encryptedAESKey": encrypted_aes,
            }
        )
        return jsonify(response)

    @app.post("/api/key-exchange")
    def key_exchange():
        me_info = key_manager.read_me_info()
        if not me_info.client_name or not me_info.client_id:
            return jsonify({"error": "请先注册或登录客户端"}), 400
        if not key_manager.public_key_exists():
            return jsonify({"error": "请先生成公钥"}), 400

        try:
            client = get_remote_client()
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"读取服务器配置失败: {exc}"}), 500

        try:
            public_key = key_manager.load_public_key_b64()
            data = client.key_exchange(public_key)
        except (RemoteClientError, FileNotFoundError) as exc:
            return jsonify({"error": str(exc)}), 502

        encrypted_aes = data.get("encryptedAESKey")
        if encrypted_aes:
            try:
                aes_key = key_manager.decrypt_aes_key(encrypted_aes)
                state_store.record_aes_key(aes_key)
            except Exception as exc:  # pylint: disable=broad-except
                return jsonify({"error": f"解密服务器返回的 AES 密钥失败: {exc}"}), 500

        response = serialize_state()
        response.update(
            {
                "message": data.get("message", "密钥交换成功"),
                "encryptedAESKey": encrypted_aes,
            }
        )
        return jsonify(response)

    @app.post("/api/keys")
    def generate_keys():
        me_info = key_manager.read_me_info()
        if not me_info.client_name or not me_info.client_id:
            return jsonify({"error": "请先注册或登录客户端"}), 400

        key_manager.rotate_keys(me_info.client_name, me_info.client_id)
        state_store.clear()

        response = serialize_state()
        response.update(
            {
                "message": "已生成新的密钥对，请重新上传公钥并执行密钥交换。",
            }
        )
        return jsonify(response)

    @app.post("/api/upload-local")
    def upload_local_file():
        if not transfer_file.exists():
            return jsonify({"error": "找不到 transfer.info，请先配置客户端。"}), 400
        if "file" not in request.files:
            return jsonify({"error": "请选择需要上传的文件"}), 400
        file = request.files["file"]
        if not file or not file.filename:
            return jsonify({"error": "请选择需要上传的文件"}), 400

        filename = secure_filename(file.filename)
        uploads_dir = base_dir / "uploads"
        uploads_dir.mkdir(parents=True, exist_ok=True)
        destination = uploads_dir / filename
        file.save(destination)

        transfer_file.update(file_path=str(destination))

        response = serialize_state()
        response.update(
            {
                "message": "文件已保存至本地临时目录，并更新 transfer.info，您可直接在此界面触发发送。",
            }
        )
        return jsonify(response)

    @app.post("/api/upload-and-send")
    def upload_and_send():
        if not transfer_file.exists():
            return jsonify({"error": "找不到 transfer.info，请先配置客户端。"}), 400
        if "file" not in request.files:
            return jsonify({"error": "请选择需要上传的文件"}), 400
        file = request.files["file"]
        if not file or not file.filename:
            return jsonify({"error": "请选择需要上传的文件"}), 400

        filename = secure_filename(file.filename)
        uploads_dir = base_dir / "uploads"
        uploads_dir.mkdir(parents=True, exist_ok=True)
        destination = uploads_dir / filename
        file.save(destination)

        try:
            transfer_file.update(file_path=str(destination))
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"写入 transfer.info 失败: {exc}"}), 500

        try:
            client = get_remote_client()
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"读取服务器配置失败: {exc}"}), 500

        try:
            server_response = perform_send(destination, client)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except RemoteClientError as exc:
            return jsonify({"error": str(exc)}), 502
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"上传失败: {exc}"}), 500

        server_message = server_response.get("message", "文件已发送")
        final_message = "文件已保存并发送"
        if server_message and server_message != "文件已发送":
            final_message = f"文件已保存并发送：{server_message}"

        response = serialize_state()
        response.update(
            {
                "message": final_message,
                "serverCrc": server_response.get("crc"),
                "serverFileSize": server_response.get("fileSize"),
                "savedPath": str(destination),
            }
        )
        return jsonify(response)

    @app.post("/api/send")
    def send_file():
        if not transfer_file.exists():
            return jsonify({"error": "找不到 transfer.info，请先配置客户端。"}), 400

        try:
            info = transfer_file.read()
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"读取 transfer.info 失败: {exc}"}), 400

        if not info.file_path:
            return jsonify({"error": "transfer.info 中缺少待发送文件路径，请先在上方“文件准备”中选择文件。"}), 400

        file_path = Path(info.file_path).expanduser()
        if not file_path.is_file():
            return jsonify({"error": "待发送文件不存在或已被移动，请重新选择。"}), 400

        try:
            client = get_remote_client()
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"读取服务器配置失败: {exc}"}), 500

        try:
            server_response = perform_send(file_path, client)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except RemoteClientError as exc:
            return jsonify({"error": str(exc)}), 502
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"上传失败: {exc}"}), 500

        response = serialize_state()
        response.update(
            {
                "message": server_response.get("message", "文件已发送"),
                "serverCrc": server_response.get("crc"),
                "serverFileSize": server_response.get("fileSize"),
            }
        )
        return jsonify(response)

    @app.get("/public-key")
    def download_public_key():
        if not key_manager.public_key_exists():
            return jsonify({"error": "尚未生成公钥"}), 404
        return send_file(
            key_manager.public_key_path,
            mimetype="text/plain",
            as_attachment=True,
            download_name="client_public.key",
        )

    return app


def run():
    app = create_app()
    app.run(host="127.0.0.1", port=DEFAULT_BIND_PORT, debug=False)
