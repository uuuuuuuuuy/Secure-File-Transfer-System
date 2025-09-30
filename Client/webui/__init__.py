"""Client-side web UI for managing registration and key exchange."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from .config import (
    DEFAULT_BIND_PORT,
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
            "clientName": transfer_info.client_name if transfer_info else me_info.client_name,
            "clientId": me_info.client_id,
            "filePath": transfer_info.file_path if transfer_info else None,
            "registered": bool(me_info.client_id),
            "hasAesKey": bool(state.get("has_aes_key")),
            "lastKeyExchange": state.get("last_key_exchange"),
            "publicKeyFingerprint": key_manager.public_key_fingerprint(),
            "publicKeyCreatedAt": key_manager.public_key_created_at(),
        }

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.get("/api/state")
    def get_state():
        return jsonify(serialize_state())

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
                "message": "文件已保存至本地临时目录，并更新 transfer.info，您可以运行原有客户端发送文件。",
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
