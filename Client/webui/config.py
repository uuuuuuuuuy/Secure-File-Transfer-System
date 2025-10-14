"""Configuration helpers for the client web UI."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


DEFAULT_REMOTE_HTTP_PORT = int(os.environ.get("CLIENT_WEBUI_REMOTE_HTTP_PORT", 5000))
DEFAULT_REMOTE_BASE_URL = os.environ.get("CLIENT_WEBUI_REMOTE_BASE_URL")
DEFAULT_BIND_PORT = int(os.environ.get("CLIENT_WEBUI_PORT", 5080))
DEFAULT_SERVER_HOST = os.environ.get("CLIENT_WEBUI_DEFAULT_SERVER_HOST", "127.0.0.1")
DEFAULT_SERVER_TCP_PORT = int(os.environ.get("CLIENT_WEBUI_DEFAULT_SERVER_TCP_PORT", 9934))


@dataclass
class TransferInfo:
    server_host: str
    server_tcp_port: int
    client_name: Optional[str]
    file_path: Optional[str]
    server_http_port: Optional[int] = None

    @property
    def server_tcp_endpoint(self) -> str:
        return f"{self.server_host}:{self.server_tcp_port}"

    def server_http_port_or_default(self) -> int:
        """Return the configured HTTP port or fall back to the default."""

        return self.server_http_port or DEFAULT_REMOTE_HTTP_PORT

    def server_http_endpoint(self) -> str:
        return f"{self.server_host}:{self.server_http_port_or_default()}"


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
        http_port = None
        if len(lines) > 3 and lines[3].strip():
            http_port = int(lines[3].strip())

        return TransferInfo(host, port, client_name, file_path, http_port)

    def update(self, *, client_name: Optional[str] = None, file_path: Optional[str] = None) -> TransferInfo:
        info = self.read()
        return self.write(
            info.server_host,
            info.server_tcp_port,
            client_name=client_name if client_name is not None else info.client_name,
            file_path=file_path if file_path is not None else info.file_path,
            server_http_port=info.server_http_port,
        )

    def write(
        self,
        server_host: str,
        server_tcp_port: int,
        *,
        client_name: Optional[str] = None,
        file_path: Optional[str] = None,
        server_http_port: Optional[int] = None,
    ) -> TransferInfo:
        host = server_host.strip()
        if not host:
            raise ValueError("server_host 不能为空")

        lines = [f"{host}:{int(server_tcp_port)}"]
        lines.append(client_name or "")
        lines.append(file_path or "")
        lines.append(str(server_http_port) if server_http_port is not None else "")

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return TransferInfo(host, int(server_tcp_port), client_name, file_path, server_http_port)

    def ensure_defaults(
        self,
        *,
        server_host: str = DEFAULT_SERVER_HOST,
        server_tcp_port: int = DEFAULT_SERVER_TCP_PORT,
        server_http_port: Optional[int] = None,
    ) -> TransferInfo:
        """Ensure transfer.info exists with sensible defaults.

        Returns the existing or newly written configuration so the caller can
        immediately use it for state serialisation.
        """

        if self.exists():
            return self.read()

        return self.write(
            server_host,
            server_tcp_port,
            client_name=None,
            file_path=None,
            server_http_port=server_http_port,
        )


def resolve_remote_base(info: TransferInfo) -> str:
    """Return the base URL for the server HTTP API."""

    if DEFAULT_REMOTE_BASE_URL:
        return DEFAULT_REMOTE_BASE_URL.rstrip("/")

    return f"http://{info.server_host}:{info.server_http_port_or_default()}".rstrip("/")


def get_base_dir() -> Path:
    return Path(__file__).resolve().parent.parent
