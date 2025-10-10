import base64
import binascii
import os
import sys
from typing import Optional

from flask import Flask, jsonify, render_template, request, session

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.append(PARENT_DIR)

from database_handler import DatabaseHandler  # noqa: E402  pylint: disable=wrong-import-position
from encryption_handler import EncryptionHandler  # noqa: E402  pylint: disable=wrong-import-position
from files_handler import FilesHandler  # noqa: E402  pylint: disable=wrong-import-position
from verification import is_valid_client_id, is_valid_client_name  # noqa: E402  pylint: disable=wrong-import-position


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(CURRENT_DIR, "templates"),
        static_folder=os.path.join(CURRENT_DIR, "static"),
    )
    app.config["SECRET_KEY"] = os.environ.get("WEBUI_SECRET_KEY", "development-secret-key")

    database_handler = DatabaseHandler()
    encryption_handler = EncryptionHandler()
    files_handler = FilesHandler()

    def _session_client_id_bytes() -> Optional[bytes]:
        client_id = session.get("client_id")
        if not client_id:
            return None
        try:
            return bytes.fromhex(client_id)
        except (ValueError, TypeError):
            return DatabaseHandler._normalize_client_id(client_id)  # type: ignore[attr-defined]

    def _store_aes_key_in_session(client_name: str) -> Optional[str]:
        aes_key = database_handler.get_AES_key(client_name)
        if aes_key is None:
            return None
        if isinstance(aes_key, bytes):
            aes_key = aes_key.decode()
        session["aes_key"] = aes_key
        return aes_key

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.get("/api/session")
    def get_session_state():
        client_id = session.get("client_id")
        client_name = session.get("client_name")
        has_aes = "aes_key" in session
        client_id_bytes = _session_client_id_bytes()
        file_count = 0
        if client_id_bytes:
            file_count = len(database_handler.list_files_for_client(client_id_bytes))
        return jsonify(
            {
                "clientId": client_id,
                "clientName": client_name,
                "hasAesKey": has_aes,
                "fileCount": file_count,
            }
        )

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
            database_handler.update_last_seen(client_id_bytes)

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
            database_handler.update_last_seen(client_id_bytes)

        return jsonify(
            {
                "clientId": session.get("client_id"),
                "encryptedAESKey": encrypted_aes,
                "hasAesKey": aes_key is not None,
                "message": "AES 密钥已下发，请使用私钥解密。",
            }
        )

    @app.post("/api/files")
    def upload_file():
        if "client_name" not in session or "aes_key" not in session:
            return jsonify({"error": "请先完成注册及密钥交换"}), 401

        payload = request.get_json(silent=True) or {}
        file_name = str(payload.get("fileName", "")).strip()
        encrypted_file = payload.get("encryptedFile")
        file_size = payload.get("fileSize")

        if not file_name or not encrypted_file:
            return jsonify({"error": "缺少文件或文件名"}), 400

        if file_size is None:
            return jsonify({"error": "缺少文件大小"}), 400

        try:
            file_size = int(file_size)
        except (ValueError, TypeError):
            return jsonify({"error": "文件大小非法"}), 400

        try:
            encrypted_bytes = base64.b64decode(encrypted_file)
        except (binascii.Error, ValueError):
            return jsonify({"error": "加密文件内容不是有效的 Base64"}), 400

        aes_key = session["aes_key"]
        decrypted_content = encryption_handler.decrypt_file(
            encrypted_bytes, aes_key, file_name
        )

        files_handler.save_decrypted_file(session["client_name"], file_name, decrypted_content)

        client_id_bytes = _session_client_id_bytes()
        database_handler.update_file_info(client_id_bytes, session["client_name"], file_name)
        database_handler.update_crc(client_id_bytes, False)
        crc_value = encryption_handler.calculate_crc(session["client_name"], file_name)
        if client_id_bytes:
            database_handler.update_last_seen(client_id_bytes)

        return jsonify(
            {
                "crc": crc_value,
                "message": "文件已成功接收并保存。",
                "fileSize": file_size,
            }
        )

    @app.get("/api/files")
    def list_files():
        if "client_name" not in session:
            return jsonify({"files": []})

        client_id_bytes = _session_client_id_bytes()
        files = database_handler.list_files_for_client(client_id_bytes)
        return jsonify({"files": files})

    return app
