import ast
import threading
import os
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional


DATABASE_FILE = "server.db"
DATABASE_SCHEMA = """
        CREATE TABLE IF NOT EXISTS clients (
            ClientID BLOB(16) PRIMARY KEY,
            Name TEXT NOT NULL,
            PublicKey BLOB(160) NOT NULL,
            LastSeen TEXT NOT NULL,
            AESKey BLOB(16) NOT NULL,
            LastIP TEXT
        );
        CREATE TABLE IF NOT EXISTS files (
            ID BLOB(16) PRIMARY KEY,
            FileName TEXT NOT NULL,
            PathName TEXT NOT NULL,
            Verified BOOLEAN NOT NULL DEFAULT 0
        );
    """

TRANSFERS_SCHEMA = """
        CREATE TABLE IF NOT EXISTS transfers (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            ClientID BLOB(16) NOT NULL,
            ClientName TEXT NOT NULL,
            FileName TEXT NOT NULL,
            FileSize INTEGER NOT NULL,
            SavedPath TEXT NOT NULL,
            SourceIP TEXT,
            ReceivedAt TEXT NOT NULL,
            Verified BOOLEAN NOT NULL DEFAULT 0,
            CRC TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_transfers_client ON transfers (ClientID);
        CREATE INDEX IF NOT EXISTS idx_transfers_received_at ON transfers (ReceivedAt DESC);
    """


class DatabaseHandler:
    def __init__(self):
        self.lock = threading.Lock()
        self.connection = None
        if self.is_database_exists():
            try:
                self.connection = sqlite3.connect(
                    DATABASE_FILE, check_same_thread=False)
            except sqlite3.Error as e:
                print(f"Error connecting to database '{DATABASE_FILE}': {e}")

        else:
            print("Creating a new database...")
            try:
                self.connection = sqlite3.connect(
                    DATABASE_FILE, check_same_thread=False)
                self.connection.executescript(DATABASE_SCHEMA)
                self.connection.executescript(TRANSFERS_SCHEMA)
                self.connection.commit()
                print(f"Database '{DATABASE_FILE}' created successfully")
            except sqlite3.Error as e:
                print(f"Error creating database '{DATABASE_FILE}': {e}")

        if self.connection is not None:
            self._ensure_additional_schema()

    def __enter__(self):
        if not self.is_database_exists():
            self.create_database()
        self.connection = sqlite3.connect(self.DATABASE_FILE)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection is not None:
            self.connection.close()

    def create_database(self):
        with self.connection as connection:
            connection.executescript(self.DATABASE_SCHEMA)

    def register_client(self, client_name, client_ip=None):

        # Generate a new client id:
        generated_uuid = uuid.uuid4()
        # Ensure UUID doesn't exceed 16 bytes
        client_id = generated_uuid.bytes[:16]

        public_key = str()
        aes_key = str()
        last_seen = self.get_last_seen()

        with self.lock:  # Avoid a case of concurrent same username registration
            # Acquire the lock to ensure mutual exclusion
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute(
                    "INSERT INTO clients (ClientID, Name, PublicKey, LastSeen, AESKey, LastIP) VALUES (?, ?, ?, ?, ?, ?)",
                    (client_id, client_name, public_key, last_seen, aes_key, client_ip))
                connection.commit()

        return client_id

    @staticmethod
    def is_database_exists():
        return os.path.isfile(DATABASE_FILE)

    def is_client_exists(self, client_name):
        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute(
                    "SELECT * FROM clients WHERE Name = ?", (client_name,))
                row = cursor.fetchone()
                return row is not None and row[1] != ""

    def is_RSA_key_exists(self, client_name):
        if not self.is_client_exists(client_name):
            return False

        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute(
                    "SELECT PublicKey FROM clients WHERE Name = ?", (client_name,))
                row = cursor.fetchone()
                return row is not None and row[0] != ""

    def get_public_RSA_key(self, client_name):
        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                query = "SELECT PublicKey FROM clients WHERE Name = ?"
                cursor.execute(query, (client_name,))
                result = cursor.fetchone()
                return result[0]

    def get_client_id(self, client_name):
        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                query = "SELECT ClientID FROM clients WHERE Name = ?"
                cursor.execute(query, (client_name,))
                result = cursor.fetchone()
                return result[0]

    def get_client_name(self, client_id):
        normalized_id = self._normalize_client_id(client_id)
        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                query = "SELECT Name FROM clients WHERE ClientID = ?"
                cursor.execute(query, (normalized_id,))
                result = cursor.fetchone()
                return result[0] if result is not None else None

    def does_client_match_id(self, client_name, client_id):
        normalized_id = self._normalize_client_id(client_id)
        if normalized_id is None:
            return False

        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute(
                    "SELECT 1 FROM clients WHERE Name = ? AND ClientID = ?",
                    (client_name, normalized_id))
                return cursor.fetchone() is not None

    def get_AES_key(self, client_name):
        client_name = str(client_name)
        with self.connection as connection:
            cursor = connection.cursor()
            query = "SELECT AESKey FROM clients WHERE Name = ?"
            cursor.execute(query, (client_name,))
            result = cursor.fetchone()
            return result[0]

    def update_public_RSA_key(self, client_name, public_key):
        client_name = str(client_name)

        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute(
                    "UPDATE clients SET PublicKey = ? WHERE Name = ?", (public_key, client_name))
                connection.commit()

    def update_AES_key(self, client_name, new_AES_key):
        client_name = str(client_name)
        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute(
                    "UPDATE clients SET AESKey = ? WHERE Name = ?", (new_AES_key, client_name))
                connection.commit()

    def update_last_seen(self, client_id, client_ip=None):
        normalized_id = self._normalize_client_id(client_id)
        if normalized_id is None:
            return

        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                last_seen = self.get_last_seen()
                if client_ip:
                    cursor.execute(
                        "UPDATE clients SET LastSeen = ?, LastIP = ? WHERE ClientID = ?",
                        (last_seen, client_ip, normalized_id))
                else:
                    cursor.execute(
                        "UPDATE clients SET LastSeen = ? WHERE ClientID = ?",
                        (last_seen, normalized_id))
                connection.commit()

    @staticmethod
    def get_last_seen():
        current_time = datetime.now()
        return current_time.strftime("%Y-%m-%d %H:%M:%S")

    def update_file_info(self, client_id, client_name, file_name):
        normalized_id = self._normalize_client_id(client_id)
        if normalized_id is None:
            return

        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                file_path = os.path.join(client_name, file_name)
                cursor.execute(
                    """
                    INSERT INTO files (ID, FileName, PathName, Verified)
                    VALUES (?, ?, ?, 0)
                    ON CONFLICT(ID) DO UPDATE SET
                        FileName = excluded.FileName,
                        PathName = excluded.PathName,
                        Verified = 0
                    """,
                    (normalized_id, str(file_name), str(file_path)))
                connection.commit()

    def update_crc(self, client_id, crc):
        normalized_id = self._normalize_client_id(client_id)
        if normalized_id is None:
            return

        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute(
                    "UPDATE files SET Verified = ? WHERE ID = ?", (crc, normalized_id))
                cursor.execute(
                    """
                    UPDATE transfers
                    SET Verified = ?
                    WHERE ID = (
                        SELECT ID FROM transfers
                        WHERE ClientID = ?
                        ORDER BY ReceivedAt DESC, ID DESC
                        LIMIT 1
                    )
                    """,
                    (int(bool(crc)), normalized_id))
                connection.commit()

    def set_transfer_verified(self, transfer_id: int, verified: bool) -> bool:
        """Mark a specific transfer row as verified/unverified."""

        if not isinstance(transfer_id, int):
            raise TypeError("transfer_id must be an integer")

        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute(
                    "SELECT ClientID FROM transfers WHERE ID = ?",
                    (transfer_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    return False

                client_id = row[0]
                cursor.execute(
                    "UPDATE transfers SET Verified = ? WHERE ID = ?",
                    (int(bool(verified)), transfer_id),
                )
                if client_id is not None:
                    cursor.execute(
                        "UPDATE files SET Verified = ? WHERE ID = ?",
                        (int(bool(verified)), client_id),
                    )
                connection.commit()
        return True

    def list_files_for_client(self, client_id):
        normalized_id = self._normalize_client_id(client_id)
        if normalized_id is None:
            return []

        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute(
                    "SELECT FileName, PathName, Verified FROM files WHERE ID = ?",
                    (normalized_id,))
                rows = cursor.fetchall()

        files = []
        for row in rows:
            files.append({
                "file_name": row[0],
                "path_name": row[1],
                "verified": bool(row[2])
            })
        return files

    def record_transfer(
        self,
        client_id,
        client_name,
        file_name,
        file_size,
        saved_path,
        source_ip=None,
        crc_value: Optional[str] = None,
    ):
        normalized_id = self._normalize_client_id(client_id)
        if normalized_id is None:
            return

        timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"

        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute(
                    """
                    INSERT INTO transfers (
                        ClientID,
                        ClientName,
                        FileName,
                        FileSize,
                        SavedPath,
                        SourceIP,
                        ReceivedAt,
                        CRC
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        normalized_id,
                        str(client_name),
                        str(file_name),
                        int(file_size),
                        str(saved_path),
                        source_ip,
                        timestamp,
                        crc_value,
                    ),
                )
                connection.commit()

    def list_clients_with_stats(self) -> List[Dict[str, Any]]:
        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute(
                    """
                    SELECT
                        c.ClientID,
                        c.Name,
                        c.LastSeen,
                        c.PublicKey,
                        c.AESKey,
                        c.LastIP,
                        COALESCE(stats.file_count, 0) AS file_count,
                        COALESCE(stats.last_received, '') AS last_received
                    FROM clients c
                    LEFT JOIN (
                        SELECT ClientID, COUNT(*) AS file_count, MAX(ReceivedAt) AS last_received
                        FROM transfers
                        GROUP BY ClientID
                    ) stats ON stats.ClientID = c.ClientID
                    ORDER BY c.LastSeen DESC
                    """
                )
                rows = cursor.fetchall()

        clients: List[Dict[str, Any]] = []
        for row in rows:
            client_id_bytes = row[0]
            client_id_hex = (
                client_id_bytes.hex()
                if isinstance(client_id_bytes, (bytes, bytearray))
                else str(client_id_bytes)
            )
            clients.append(
                {
                    "clientId": client_id_hex,
                    "clientName": row[1],
                    "lastSeen": row[2],
                    "hasPublicKey": bool(row[3]),
                    "hasAesKey": bool(row[4]),
                    "lastIp": row[5],
                    "fileCount": row[6],
                    "lastReceivedAt": row[7],
                }
            )
        return clients

    def list_transfers(self, client_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        normalized_id = None
        if client_id is not None:
            normalized_id = self._normalize_client_id(client_id)

        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                if normalized_id is not None:
                    cursor.execute(
                        """
                        SELECT ID, ClientID, ClientName, FileName, FileSize, SavedPath, SourceIP, ReceivedAt, Verified, CRC
                        FROM transfers
                        WHERE ClientID = ?
                        ORDER BY ReceivedAt DESC, ID DESC
                        LIMIT ?
                        """,
                        (normalized_id, limit),
                    )
                else:
                    cursor.execute(
                        """
                        SELECT ID, ClientID, ClientName, FileName, FileSize, SavedPath, SourceIP, ReceivedAt, Verified, CRC
                        FROM transfers
                        ORDER BY ReceivedAt DESC, ID DESC
                        LIMIT ?
                        """,
                        (limit,),
                    )
                rows = cursor.fetchall()

        transfers: List[Dict[str, Any]] = []
        for row in rows:
            transfer_id = int(row[0])
            client_id_bytes = row[1]
            client_id_hex = (
                client_id_bytes.hex()
                if isinstance(client_id_bytes, (bytes, bytearray))
                else str(client_id_bytes)
            )
            transfers.append(
                {
                    "transferId": transfer_id,
                    "clientId": client_id_hex,
                    "clientName": row[2],
                    "fileName": row[3],
                    "fileSize": row[4],
                    "savedPath": row[5],
                    "sourceIp": row[6],
                    "receivedAt": row[7],
                    "verified": bool(row[8]),
                    "crcValue": row[9],
                }
            )
        return transfers

    def list_storage_directories(self) -> List[str]:
        """Return absolute directories that contain saved transfer files."""
        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute("SELECT DISTINCT SavedPath FROM transfers WHERE SavedPath != ''")
                rows = cursor.fetchall()

        directories: List[str] = []
        seen = set()
        for (path,) in rows:
            if not path:
                continue
            directory = os.path.dirname(path)
            if not directory:
                continue
            normalized = os.path.abspath(directory)
            if normalized not in seen:
                seen.add(normalized)
                directories.append(normalized)

        directories.sort(key=lambda item: item.lower())
        return directories

    def get_overview_stats(self) -> Dict[str, int]:
        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute("SELECT COUNT(*) FROM clients")
                client_count = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM transfers")
                transfer_count = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM transfers WHERE Verified = 1")
                verified_count = cursor.fetchone()[0]
        return {
            "clientCount": client_count,
            "transferCount": transfer_count,
            "verifiedCount": verified_count,
        }

    def _ensure_additional_schema(self):
        with self.lock:
            with self.connection as connection:
                cursor = connection.cursor()
                cursor.execute("PRAGMA table_info(clients)")
                columns = {row[1] for row in cursor.fetchall()}
                if "LastIP" not in columns:
                    cursor.execute("ALTER TABLE clients ADD COLUMN LastIP TEXT")
                cursor.execute("PRAGMA table_info(transfers)")
                transfer_columns = {row[1] for row in cursor.fetchall()}
                if "CRC" not in transfer_columns:
                    cursor.execute("ALTER TABLE transfers ADD COLUMN CRC TEXT")
                connection.executescript(TRANSFERS_SCHEMA)
                connection.commit()

    @staticmethod
    def _normalize_client_id(client_id):
        if client_id is None:
            return None

        if isinstance(client_id, memoryview):
            client_id = client_id.tobytes()

        if isinstance(client_id, bytearray):
            client_id = bytes(client_id)

        if isinstance(client_id, bytes):
            return client_id

        if isinstance(client_id, str):
            candidate = client_id.strip()
            if not candidate:
                return None

            try:
                return bytes.fromhex(candidate)
            except ValueError:
                pass

            if candidate.startswith("b'") or candidate.startswith('b"'):
                try:
                    literal = ast.literal_eval(candidate)
                    if isinstance(literal, (bytes, bytearray)):
                        return bytes(literal)
                except (ValueError, SyntaxError):
                    pass

            return candidate.encode()

        raise TypeError(
            f"Unsupported client id type: {type(client_id)}")
