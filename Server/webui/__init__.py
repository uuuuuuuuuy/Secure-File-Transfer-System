import os
import sys

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

    return app
