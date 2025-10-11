import os
import sys
from datetime import datetime

from flask import Flask, jsonify, render_template, request

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.append(PARENT_DIR)

from database_handler import DatabaseHandler  # noqa: E402  pylint: disable=wrong-import-position


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(CURRENT_DIR, "templates"),
        static_folder=os.path.join(CURRENT_DIR, "static"),
    )
    app.config["SECRET_KEY"] = os.environ.get("WEBUI_SECRET_KEY", "development-secret-key")

    database_handler = DatabaseHandler()

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.get("/api/overview")
    def get_overview():
        return jsonify(database_handler.get_overview_stats())

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
