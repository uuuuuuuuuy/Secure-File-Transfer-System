"""HTTP helper that proxies requests to the server web UI."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import requests
from requests import exceptions as requests_exceptions


class RemoteClientError(Exception):
    """Raised when remote interactions fail."""


class RemoteClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def _request(
        self, method: str, path: str, *, json: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, Dict[str, Any]]:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(method, url, json=json, timeout=10)
        except requests_exceptions.RequestException as exc:
            raise RemoteClientError(f"无法连接到服务器: {exc}") from exc
        try:
            payload = response.json()
        except ValueError:
            payload = {"error": response.text or "服务器返回了无效的响应"}
        if response.status_code >= 400:
            message = payload.get("error") if isinstance(payload, dict) else None
            raise RemoteClientError(message or f"请求失败，状态码 {response.status_code}")
        if not isinstance(payload, dict):
            raise RemoteClientError("服务器返回了意料之外的格式")
        return response.status_code, payload

    def register(self, client_name: str) -> Dict[str, Any]:
        _, data = self._request("POST", "/api/register", json={"clientName": client_name})
        return data

    def login(self, client_name: str, client_id: str) -> Dict[str, Any]:
        _, data = self._request(
            "POST", "/api/login", json={"clientName": client_name, "clientId": client_id}
        )
        return data

    def key_exchange(self, public_key: str) -> Dict[str, Any]:
        _, data = self._request("POST", "/api/key-exchange", json={"publicKey": public_key})
        return data

    def upload_file(self, filename: str, payload: str, plain_size: int) -> Dict[str, Any]:
        _, data = self._request(
            "POST",
            "/api/upload",
            json={"fileName": filename, "payload": payload, "plainSize": plain_size},
        )
        return data

