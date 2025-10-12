import base64
import binascii
import os
import socket
import sys
from datetime import datetime
from urllib.parse import urlparse

from flask import Flask, jsonify, render_template, request, session

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.append(PARENT_DIR)

from database_handler import DatabaseHandler  # noqa: E402  pylint: disable=wrong-import-position
from encryption_handler import (  # noqa: E402  pylint: disable=wrong-import-position
    EncryptionHandler,
)
from files_handler import FilesHandler  # noqa: E402  pylint: disable=wrong-import-position
from verification import (  # noqa: E402  pylint: disable=wrong-import-position
    is_valid_client_name,
)


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

    def get_remote_ip():
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return request.remote_addr

    def require_active_client():
        client_id = session.get("client_id")
        client_name = session.get("client_name")
        if not client_id or not client_name:
            return None
        return client_id, client_name

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.get("/api/overview")
    def get_overview():
        return jsonify(database_handler.get_overview_stats())

    @app.get("/api/server-info")
    def get_server_info():
        parsed = urlparse(request.host_url)
        http_scheme = parsed.scheme or request.environ.get("wsgi.url_scheme", "http")
        http_host = parsed.hostname or (request.host.split(":", 1)[0] if request.host else "localhost")

        http_port = parsed.port
        if http_port is None:
            environ_port = request.environ.get("SERVER_PORT")
            try:
                http_port = int(environ_port)
            except (TypeError, ValueError):
                http_port = 80 if http_scheme == "http" else 443

        tcp_bind_host = (
            os.environ.get("SERVER_TCP_HOST")
            or os.environ.get("SERVER_HOST")
            or os.environ.get("TCP_HOST")
            or "0.0.0.0"
        )
        tcp_host = tcp_bind_host
        if tcp_host in {None, "", "0.0.0.0", "::"}:
            tcp_host = http_host
            if tcp_host in {None, "", "0.0.0.0", "::"}:
                try:
                    tcp_host = socket.gethostbyname(socket.gethostname())
                except OSError:
                    tcp_host = "127.0.0.1"

        return jsonify(
            {
                "httpScheme": http_scheme,
                "httpHost": http_host,
                "httpPort": http_port,
                "httpUrl": request.host_url.rstrip("/"),
                "tcpHost": tcp_host,
                "tcpBindHost": tcp_bind_host,
                "tcpPort": files_handler.port,
            }
        )

    @app.get("/api/clients")
    def list_clients():
        clients = database_handler.list_clients_with_stats()
        return jsonify({"clients": clients})

    @app.get("/api/transfers")
    def list_transfers():
        client_id = request.args.get("clientId")
        limit = request.args.get("limit", default=50, type=int) or 50
        limit = max(1, min(limit, 500))
        transfers = database_handler.list_transfers(client_id, limit)
        return jsonify({"transfers": transfers})

    @app.post("/api/register")
    def register_client():
        payload = request.get_json(silent=True) or {}
        client_name = str(payload.get("clientName", "")).strip()
        if not client_name:
            return jsonify({"error": "请输入客户端名称"}), 400
        if not is_valid_client_name(client_name):
            return jsonify({"error": "客户端名称仅支持字母、数字与空格"}), 400
        if database_handler.is_client_exists(client_name):
            return jsonify({"error": "该客户端名称已被注册，请直接登录"}), 409

        try:
            client_id_bytes = database_handler.register_client(client_name, get_remote_ip())
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"注册失败：{exc}"}), 500

        client_id_hex = client_id_bytes.hex()
        session["client_id"] = client_id_hex
        session["client_name"] = client_name
        session.modified = True

        database_handler.update_last_seen(client_id_hex, get_remote_ip())

        return (
            jsonify(
                {
                    "message": "注册成功",
                    "clientId": client_id_hex,
                    "clientName": client_name,
                    "hasPublicKey": False,
                    "hasAesKey": False,
                }
            ),
            201,
        )

    @app.post("/api/login")
    def login_client():
        payload = request.get_json(silent=True) or {}
        client_name = str(payload.get("clientName", "")).strip()
        client_id = str(payload.get("clientId", "")).strip()

        if not client_name or not client_id:
            return jsonify({"error": "请输入客户端名称与 ID"}), 400
        if not database_handler.does_client_match_id(client_name, client_id):
            return jsonify({"error": "未找到匹配的客户端，请确认名称与 ID"}), 404

        session["client_id"] = client_id
        session["client_name"] = client_name
        session.modified = True

        has_public_key = database_handler.is_RSA_key_exists(client_name)
        encrypted_aes = None
        message = "登录成功"

        if has_public_key:
            try:
                encryption_handler.generate_AES_key(client_name)
                encrypted_aes = encryption_handler.get_encrypted_AES_key(client_name)
                message = "登录成功，已生成新的 AES 密钥"
            except Exception as exc:  # pylint: disable=broad-except
                return jsonify({"error": f"生成 AES 密钥失败：{exc}"}), 500
        else:
            message = "登录成功，请先上传公钥并执行密钥交换"

        database_handler.update_last_seen(client_id, get_remote_ip())

        return jsonify(
            {
                "message": message,
                "clientId": client_id,
                "clientName": client_name,
                "encryptedAESKey": encrypted_aes,
                "hasPublicKey": has_public_key,
                "hasAesKey": bool(encrypted_aes),
            }
        )

    @app.post("/api/key-exchange")
    def upload_public_key():
        identity = require_active_client()
        if identity is None:
            return jsonify({"error": "会话已失效，请重新登录后再试"}), 401

        client_id, client_name = identity
        payload = request.get_json(silent=True) or {}
        public_key = str(payload.get("publicKey", "")).strip()
        if not public_key:
            return jsonify({"error": "缺少公钥内容"}), 400

        try:
            database_handler.update_public_RSA_key(client_name, public_key)
            encryption_handler.generate_AES_key(client_name)
            encrypted_aes = encryption_handler.get_encrypted_AES_key(client_name)
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"处理公钥时发生错误：{exc}"}), 500

        database_handler.update_last_seen(client_id, get_remote_ip())

        return jsonify(
            {
                "message": "公钥已更新并生成新的 AES 密钥",
                "clientId": client_id,
                "clientName": client_name,
                "encryptedAESKey": encrypted_aes,
                "hasPublicKey": True,
                "hasAesKey": True,
            }
        )

    @app.post("/api/files")
    def upload_encrypted_file():
        identity = require_active_client()
        if identity is None:
            return jsonify({"error": "会话已失效，请重新登录后再试"}), 401

        client_id, client_name = identity
        payload = request.get_json(silent=True) or {}

        file_name = str(payload.get("fileName", "")).strip()
        encrypted_file = payload.get("encryptedFile")
        file_size = payload.get("fileSize")

        if not file_name or not encrypted_file:
            return jsonify({"error": "缺少文件名称或内容"}), 400

        aes_key = database_handler.get_AES_key(client_name)
        if not aes_key:
            return jsonify({"error": "尚未生成 AES 密钥，请先完成密钥交换"}), 400

        try:
            encrypted_bytes = base64.b64decode(encrypted_file)
        except (ValueError, binascii.Error) as exc:
            return jsonify({"error": f"解析加密文件失败：{exc}"}), 400

        try:
            decrypted_content = encryption_handler.decrypt_file(encrypted_bytes, aes_key, file_name)
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"解密文件失败：{exc}"}), 500

        try:
            saved_path = files_handler.save_decrypted_file(client_name, file_name, decrypted_content)
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"保存文件失败：{exc}"}), 500

        try:
            database_handler.update_file_info(client_id, client_name, file_name)
            database_handler.update_crc(client_id, False)
            crc = encryption_handler.calculate_crc(client_name, file_name)
            crc_hex = f"{int(crc):08X}"
            database_handler.record_transfer(
                client_id,
                client_name,
                file_name,
                int(file_size) if file_size is not None else 0,
                saved_path,
                get_remote_ip(),
                crc_hex,
            )
            database_handler.update_last_seen(client_id, get_remote_ip())
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"更新数据库失败：{exc}"}), 500

        response = {
            "message": "文件接收成功",
            "clientId": client_id,
            "clientName": client_name,
            "fileSize": int(file_size) if file_size is not None else 0,
            "crc": crc_hex,
            "savedPath": saved_path,
        }
        return jsonify(response), 201

    @app.post("/api/transfers/<int:transfer_id>/verify")
    def verify_transfer(transfer_id: int):
        payload = request.get_json(silent=True) or {}
        verified = payload.get("verified", True)
        try:
            updated = database_handler.set_transfer_verified(transfer_id, bool(verified))
        except TypeError:
            return jsonify({"error": "请求参数无效"}), 400
        except Exception as exc:  # pylint: disable=broad-except
            return jsonify({"error": f"更新校验状态失败：{exc}"}), 500

        if not updated:
            return jsonify({"error": "未找到对应的传输记录"}), 404

        message = "已标记为待确认"
        if bool(verified):
            message = "CRC 校验已确认"
        return jsonify({"message": f"传输记录 {transfer_id} {message}"})

    @app.get("/files-browser")
    def files_browser():
        directories = database_handler.list_storage_directories()
        directory_items = [
            {"path": path, "exists": os.path.isdir(path)} for path in directories
        ]

        allowed_directories = {
            os.path.abspath(item["path"]) for item in directory_items if item["exists"]
        }
        requested_path = request.args.get("path")
        target_path = None
        error_message = None

        if requested_path:
            candidate = os.path.abspath(requested_path)
        else:
            candidate = next(
                (os.path.abspath(item["path"]) for item in directory_items if item["exists"]),
                None,
            )

        entries = []
        if candidate:
            if candidate not in allowed_directories:
                error_message = "指定的目录不在已知的文件存储路径中。"
            elif not os.path.isdir(candidate):
                error_message = "目录不存在或已被移动。"
            else:
                target_path = candidate
                try:
                    for name in sorted(os.listdir(target_path)):
                        full_path = os.path.join(target_path, name)
                        try:
                            stats = os.stat(full_path)
                        except OSError:
                            continue
                        entries.append(
                            {
                                "name": name,
                                "full_path": full_path,
                                "is_dir": os.path.isdir(full_path),
                                "size": None if os.path.isdir(full_path) else stats.st_size,
                                "modified": datetime.fromtimestamp(stats.st_mtime),
                            }
                        )
                except OSError:
                    error_message = "读取目录内容时发生错误。"

        return render_template(
            "files_browser.html",
            directories=directory_items,
            current_path=target_path,
            entries=entries,
            error_message=error_message,
        )

    return app
