"""Key management utilities for the client web UI."""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@dataclass
class MeInfo:
    client_name: Optional[str]
    client_id: Optional[str]
    private_key_b64: Optional[str]


class KeyManager:
    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.me_path = self.base_dir / "me.info"
        self.public_key_path = self.base_dir / "client_public.key"

    def read_me_info(self) -> MeInfo:
        if not self.me_path.exists():
            return MeInfo(None, None, None)

        lines = self.me_path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return MeInfo(None, None, None)

        client_name = lines[0].strip() if len(lines) > 0 else None
        client_id = lines[1].strip() if len(lines) > 1 else None
        private_key = lines[2].strip() if len(lines) > 2 else None

        return MeInfo(client_name or None, client_id or None, private_key or None)

    def write_me_info(self, client_name: str, client_id: str, private_key_b64: str) -> None:
        content = f"{client_name}\n{client_id}\n{private_key_b64}\n"
        self.me_path.write_text(content, encoding="utf-8")

    def generate_key_pair(self) -> Tuple[str, str]:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        private_der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        private_b64 = base64.b64encode(private_der).decode("ascii")
        public_b64 = base64.b64encode(public_der).decode("ascii")

        self.public_key_path.write_text(public_b64 + "\n", encoding="utf-8")
        return private_b64, public_b64

    def ensure_keys(self, client_name: str, client_id: str) -> Tuple[str, str]:
        info = self.read_me_info()
        if info.client_name == client_name and info.client_id == client_id and info.private_key_b64:
            if self.public_key_path.exists():
                public_b64 = self.public_key_path.read_text(encoding="utf-8").strip()
                if public_b64:
                    return info.private_key_b64, public_b64
        private_b64, public_b64 = self.generate_key_pair()
        self.write_me_info(client_name, client_id, private_b64)
        return private_b64, public_b64

    def rotate_keys(self, client_name: str, client_id: str) -> Tuple[str, str]:
        private_b64, public_b64 = self.generate_key_pair()
        self.write_me_info(client_name, client_id, private_b64)
        return private_b64, public_b64

    def load_private_key(self) -> rsa.RSAPrivateKey:
        info = self.read_me_info()
        if not info.private_key_b64:
            raise FileNotFoundError("私钥不存在，请先生成密钥对。")

        private_der = base64.b64decode(info.private_key_b64)
        return serialization.load_der_private_key(private_der, password=None)

    def load_public_key_b64(self) -> str:
        if not self.public_key_path.exists():
            raise FileNotFoundError("公钥不存在，请先生成密钥对。")
        return self.public_key_path.read_text(encoding="utf-8").strip()

    def decrypt_aes_key(self, encrypted_aes_key_b64: str) -> str:
        encrypted_bytes = base64.b64decode(encrypted_aes_key_b64)
        private_key = self.load_private_key()
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )
        return decrypted.decode("utf-8")

    def public_key_fingerprint(self) -> Optional[str]:
        if not self.public_key_path.exists():
            return None
        raw = self.public_key_path.read_text(encoding="utf-8").strip()
        if not raw:
            return None
        decoded = base64.b64decode(raw)
        digest = hashlib.sha256(decoded).hexdigest().upper()
        return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))

    def public_key_created_at(self) -> Optional[str]:
        if not self.public_key_path.exists():
            return None
        stat = self.public_key_path.stat()
        dt = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
        return dt.isoformat()

    def public_key_exists(self) -> bool:
        return self.public_key_path.exists() and bool(self.public_key_path.read_text(encoding="utf-8").strip())
