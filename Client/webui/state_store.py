"""Persistence helpers for the client web UI."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


class StateStore:
    def __init__(self, base_dir: Path):
        self.path = base_dir / ".client_webui_state.json"

    def load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def save(self, data: Dict[str, Any]) -> None:
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()

    def record_aes_key(self, aes_key: str) -> Dict[str, Any]:
        data = self.load()
        data["aes_key"] = aes_key
        data["has_aes_key"] = True
        data["last_key_exchange"] = datetime.now(tz=timezone.utc).isoformat()
        self.save(data)
        return data

    def get_aes_key(self) -> Optional[str]:
        data = self.load()
        return data.get("aes_key")

    def record_send(self, filename: str) -> Dict[str, Any]:
        data = self.load()
        data["last_send"] = datetime.now(tz=timezone.utc).isoformat()
        data["last_send_file"] = filename
        self.save(data)
        return data

    def status(self) -> Dict[str, Optional[str]]:
        data = self.load()
        return {
            "has_aes_key": data.get("has_aes_key", False),
            "last_key_exchange": data.get("last_key_exchange"),
            "last_send": data.get("last_send"),
            "last_send_file": data.get("last_send_file"),
        }
