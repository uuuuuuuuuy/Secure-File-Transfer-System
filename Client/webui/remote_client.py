"""HTTP helper that proxies requests to the server web UI."""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import requests
from requests import exceptions as requests_exceptions


class RemoteClientError(Exception):
    pass


class RemoteClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()

    def _request(self, method: str, path: str, *, json: Optional[Dict[str, Any]] = None) -> Tuple[int, Dict[str, Any]]:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(method, url, json=json, timeout=10)
        except requests_exceptions.RequestException as exc:
            raise RemoteClientError(
                f"无法连接到服务器 {self.base_url}：{exc}"
            ) from exc

        raw_text = response.text or ""
        payload: Dict[str, Any]
        try:
            payload = response.json() if raw_text else {}
        except ValueError:
            payload = {}

        if response.status_code >= 400:
            detail: Optional[str] = None
            if isinstance(payload, dict):
                for key in ("error", "message", "detail"):
                    value = payload.get(key)
                    if isinstance(value, str) and value.strip():
                        detail = value.strip()
                        break
            elif isinstance(payload, list) and payload:
                maybe_message = payload[0]
                if isinstance(maybe_message, str):
                    detail = maybe_message.strip()

            if not detail and raw_text:
                snippet = raw_text.strip()
                detail = snippet if len(snippet) <= 200 else f"{snippet[:200]}…"

            raise RemoteClientError(
                detail or f"请求失败（HTTP {response.status_code}）"
            )

        if payload and not isinstance(payload, dict):
            raise RemoteClientError("服务器返回了意料之外的格式")

        return response.status_code, payload

    def register(self, client_name: str) -> Dict[str, Any]:
        _, data = self._request("POST", "/api/register", json={"clientName": client_name})
        return data

    def login(self, client_name: str, client_id: str) -> Dict[str, Any]:
        _, data = self._request("POST", "/api/login", json={"clientName": client_name, "clientId": client_id})
        return data

    def key_exchange(self, public_key: str) -> Dict[str, Any]:
        _, data = self._request("POST", "/api/key-exchange", json={"publicKey": public_key})
        return data

    def upload_file(self, file_name: str, encrypted_file: str, file_size: int) -> Dict[str, Any]:
        payload = {
            "fileName": file_name,
            "encryptedFile": encrypted_file,
            "fileSize": file_size,
        }
        _, data = self._request("POST", "/api/files", json=payload)
        return data

