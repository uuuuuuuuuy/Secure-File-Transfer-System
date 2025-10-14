"""Configuration helpers for the client web UI."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


DEFAULT_REMOTE_HTTP_PORT = int(os.environ.get("CLIENT_WEBUI_REMOTE_HTTP_PORT", 5000))
DEFAULT_REMOTE_BASE_URL = os.environ.get("CLIENT_WEBUI_REMOTE_BASE_URL")
DEFAULT_BIND_PORT = int(os.environ.get("CLIENT_WEBUI_PORT", 5080))


@dataclass
class TransferInfo:
    server_host: str
    server_tcp_port: int
    client_name: Optional[str]
    file_path: Optional[str]

    @property
    def server_tcp_endpoint(self) -> str:
        return f"{self.server_host}:{self.server_tcp_port}"


class TransferFile:
    """Utility wrapper around the legacy transfer.info file."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.path = self.base_dir / "transfer.info"

    def exists(self) -> bool:
        return self.path.exists()

    def read(self) -> TransferInfo:
        if not self.path.exists():
            raise FileNotFoundError(self.path)

        lines = self.path.read_text(encoding="utf-8").splitlines()
        if not lines:
            raise ValueError("transfer.info is empty")

        endpoint = lines[0].strip()
        if ":" not in endpoint:
            raise ValueError("transfer.info first line must be IP:PORT")

        host, port_str = endpoint.split(":", 1)
        port = int(port_str)

        client_name = lines[1].strip() if len(lines) > 1 and lines[1].strip() else None
        file_path = lines[2].strip() if len(lines) > 2 and lines[2].strip() else None

        return TransferInfo(host, port, client_name, file_path)

    def update(self, *, client_name: Optional[str] = None, file_path: Optional[str] = None) -> TransferInfo:
        info = self.read()
        new_client_name = client_name if client_name is not None else info.client_name
        new_file_path = file_path if file_path is not None else info.file_path

        lines = [info.server_tcp_endpoint]
        lines.append(new_client_name or "")
        lines.append(new_file_path or "")

        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return TransferInfo(info.server_host, info.server_tcp_port, new_client_name, new_file_path)


def resolve_remote_base(info: TransferInfo) -> str:
    """Return the base URL for the server HTTP API."""

    if DEFAULT_REMOTE_BASE_URL:
        return DEFAULT_REMOTE_BASE_URL.rstrip("/")

    return f"http://{info.server_host}:{DEFAULT_REMOTE_HTTP_PORT}".rstrip("/")


def get_base_dir() -> Path:
    return Path(__file__).resolve().parent.parent
