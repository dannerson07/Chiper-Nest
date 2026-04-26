"""
╔══════════════════════════════════════════════════════════════╗
║             CIPHER NEST — Module 3: audit_db.py             ║
║         MongoDB integration — users, metadata, audit logs    ║
╚══════════════════════════════════════════════════════════════╝

Responsibilities:
  - Connect to MongoDB
  - User management (create, fetch, check existence)
  - Log every vault operation as an audit trail
  - Store file metadata (hash, vault path, status)
  - Query audit logs for display in CLI / GUI

Collections:
  ciphernest.users       — registered user accounts
  ciphernest.files       — file metadata (one doc per vaulted file)
  ciphernest.audit_logs  — every operation ever performed

Standalone usage (connection test):
  python audit_db.py

Importable usage:
  from audit_db import AuditDB
  db = AuditDB()
  db.create_user({...})
  db.log_operation(result_dict)
  db.get_logs(user_id="abc123", limit=20)
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import (
    ConnectionFailure,
    DuplicateKeyError,
    ServerSelectionTimeoutError,
)
from bson import ObjectId

# ─────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("audit_db")

# ─────────────────────────────────────────────
# Defaults
# ─────────────────────────────────────────────
DEFAULT_URI      = "mongodb://localhost:27017/"
DEFAULT_DB_NAME  = "ciphernest"
CONNECT_TIMEOUT  = 3000     # ms — fail fast if MongoDB isn't running


# ══════════════════════════════════════════════
# AuditDB
# ══════════════════════════════════════════════
class AuditDB:
    """
    Single interface for all MongoDB operations in Cipher Nest.

    Collections managed:
      users       — one doc per registered user
      files       — one doc per vaulted file (tracks status over time)
      audit_logs  — one doc per operation (insert-only, never updated)

    core.py calls this class directly. It never touches pymongo itself.

    Usage:
      db = AuditDB()                         # connects to localhost
      db = AuditDB(uri="mongodb://...")      # custom URI (Atlas, Docker, etc.)
    """

    def __init__(self, uri: str = None, db_name: str = None):
        """
        Args:
            uri     : MongoDB connection URI. Defaults to localhost:27017.
            db_name : Database name. Defaults to "ciphernest".
        """
        self._uri     = uri or DEFAULT_URI
        self._db_name = db_name or DEFAULT_DB_NAME
        self._client  = None
        self._db      = None

        self._connect()
        self._ensure_indexes()

    # ─────────────────────────────────────────
    # Connection
    # ─────────────────────────────────────────
    def _connect(self):
        """
        Connects to MongoDB. Raises ConnectionFailure if unreachable.
        serverSelectionTimeoutMS ensures we fail fast (3s) rather than hang.
        """
        try:
            self._client = MongoClient(
                self._uri,
                serverSelectionTimeoutMS=CONNECT_TIMEOUT
            )
            # Force connection check
            self._client.admin.command("ping")
            self._db = self._client[self._db_name]
            logger.info(f"Connected to MongoDB — db: '{self._db_name}'")

        except (ConnectionFailure, ServerSelectionTimeoutError) as e:
            logger.error(
                f"MongoDB connection failed: {e}\n"
                f"  URI: {self._uri}\n"
                f"  Is MongoDB running? Try: mongod --dbpath /data/db"
            )
            raise

    # ─────────────────────────────────────────
    # Indexes — created once on startup
    # ─────────────────────────────────────────
    def _ensure_indexes(self):
        """
        Creates indexes for fast lookups and uniqueness enforcement.
        Safe to run multiple times — MongoDB ignores existing indexes.
        """
        # users — username must be unique
        self._db.users.create_index(
            [("username", ASCENDING)],
            unique=True,
            name="unique_username"
        )

        # files — one file doc per user+filename combo
        self._db.files.create_index(
            [("user_id", ASCENDING), ("original_name", ASCENDING)],
            name="user_filename"
        )

        # audit_logs — query by user and sort by time
        self._db.audit_logs.create_index(
            [("user_id", ASCENDING), ("timestamp", DESCENDING)],
            name="user_logs_by_time"
        )

        logger.debug("MongoDB indexes ensured.")

    # ══════════════════════════════════════════
    # USER MANAGEMENT
    # ══════════════════════════════════════════
    def create_user(self, user_doc: dict) -> str:
        """
        Inserts a new user document into the users collection.

        Args:
            user_doc : Dict with keys: username, password_hash, created_at, vault_files.

        Returns:
            Inserted MongoDB _id as a string.

        Raises:
            ValueError if username already exists.
        """
        try:
            result  = self._db.users.insert_one(user_doc)
            user_id = str(result.inserted_id)
            logger.info(f"User created: {user_doc['username']} (id={user_id})")
            return user_id

        except DuplicateKeyError:
            raise ValueError(f"Username '{user_doc['username']}' already exists.")

    def get_user(self, username: str) -> dict | None:
        """
        Fetches a user document by username.

        Returns:
            User dict (with _id) or None if not found.
        """
        return self._db.users.find_one({"username": username})

    def user_exists(self, username: str) -> bool:
        """Returns True if username is already registered."""
        return self._db.users.count_documents({"username": username}) > 0

    def get_user_by_id(self, user_id: str) -> dict | None:
        """Fetches a user document by MongoDB _id string."""
        try:
            return self._db.users.find_one({"_id": ObjectId(user_id)})
        except Exception:
            return None

    # ══════════════════════════════════════════
    # FILE METADATA
    # ══════════════════════════════════════════
    def upsert_file_metadata(self, op_result: dict):
        """
        Creates or updates a file metadata document.
        Called after every encrypt / decrypt / open / relock / delete.

        Uses upsert so a file's doc is updated in-place as its status changes:
          vaulted → temp_out → vaulted → exported

        Args:
            op_result : MongoDB-ready dict from crypto_engine.py
        """
        if not op_result.get("user_id") or not op_result.get("original_name"):
            return  # not enough info to store

        filter_doc = {
            "user_id"       : op_result["user_id"],
            "original_name" : op_result["original_name"],
        }

        update_doc = {
            "$set": {
                "status"           : op_result.get("status"),
                "output_path"      : op_result.get("output_path"),
                "salt_path"        : op_result.get("salt_path"),
                "file_size_bytes"  : op_result.get("file_size_bytes"),
                "file_hash_sha256" : op_result.get("file_hash_sha256"),
                "last_action"      : op_result.get("action"),
                "last_updated"     : op_result.get("timestamp"),
            },
            "$setOnInsert": {
                # These fields are set only when the doc is FIRST created
                "user_id"       : op_result["user_id"],
                "original_name" : op_result["original_name"],
                "created_at"    : op_result.get("timestamp"),
            }
        }

        self._db.files.update_one(filter_doc, update_doc, upsert=True)
        logger.debug(f"File metadata upserted: {op_result['original_name']}")

    def get_user_files(self, user_id: str, status: str = None) -> list:
        """
        Returns all file metadata docs for a user.

        Args:
            user_id : MongoDB user _id string.
            status  : (Optional) Filter by status — "vaulted", "exported", etc.

        Returns:
            List of file metadata dicts.
        """
        query = {"user_id": user_id}
        if status:
            query["status"] = status

        return list(self._db.files.find(query, {"_id": 0}))

    # ══════════════════════════════════════════
    # AUDIT LOGS
    # ══════════════════════════════════════════
    def log_operation(self, op_result: dict):
        """
        Inserts an operation as an audit log entry.
        Audit logs are INSERT-ONLY — never updated, never deleted.
        Every action (even failed ones) gets a permanent record.

        Also triggers a file metadata upsert so the files collection
        stays in sync.

        Args:
            op_result : MongoDB-ready dict from crypto_engine.py
        """
        # ── Insert audit log ──
        log_doc = {
            "success"          : op_result.get("success"),
            "action"           : op_result.get("action"),
            "status"           : op_result.get("status"),
            "user_id"          : op_result.get("user_id"),
            "original_name"    : op_result.get("original_name"),
            "file_size_bytes"  : op_result.get("file_size_bytes"),
            "file_hash_sha256" : op_result.get("file_hash_sha256"),
            "output_path"      : op_result.get("output_path"),
            "timestamp"        : op_result.get("timestamp"),
            "error"            : op_result.get("error"),
        }
        self._db.audit_logs.insert_one(log_doc)
        logger.debug(f"Audit log inserted: {log_doc['action']} — {log_doc.get('original_name')}")

        # ── Keep file metadata in sync ──
        self.upsert_file_metadata(op_result)

    def get_logs(self, user_id: str, limit: int = 20, action: str = None) -> list:
        """
        Fetches audit logs for a user, newest first.

        Args:
            user_id : MongoDB user _id string.
            limit   : Max number of logs to return (default 20).
            action  : (Optional) Filter by action — "encrypt", "decrypt", etc.

        Returns:
            List of log dicts (without MongoDB _id).
        """
        query = {"user_id": user_id}
        if action:
            query["action"] = action

        return list(
            self._db.audit_logs
            .find(query, {"_id": 0})
            .sort("timestamp", DESCENDING)
            .limit(limit)
        )

    def get_all_logs(self, limit: int = 100) -> list:
        """
        Returns all audit logs across all users (admin use).
        Sorted newest first.
        """
        return list(
            self._db.audit_logs
            .find({}, {"_id": 0})
            .sort("timestamp", DESCENDING)
            .limit(limit)
        )

    def count_operations(self, user_id: str) -> dict:
        """
        Returns a summary count of operations for a user.
        Useful for a dashboard or profile page.

        Returns:
            dict — e.g. {"encrypt": 5, "decrypt": 3, "open": 8, "delete": 1}
        """
        pipeline = [
            {"$match": {"user_id": user_id}},
            {"$group": {"_id": "$action", "count": {"$sum": 1}}}
        ]
        results = self._db.audit_logs.aggregate(pipeline)
        return {doc["_id"]: doc["count"] for doc in results}

    # ══════════════════════════════════════════
    # INTEGRITY
    # ══════════════════════════════════════════
    def get_file_hash(self, user_id: str, original_name: str) -> str | None:
        """
        Fetches the stored SHA256 hash for a file from the files collection.
        Used by core.py to run integrity checks after decryption.

        Returns:
            SHA256 hex string or None if not found.
        """
        doc = self._db.files.find_one(
            {"user_id": user_id, "original_name": original_name},
            {"file_hash_sha256": 1, "_id": 0}
        )
        return doc["file_hash_sha256"] if doc else None

    # ══════════════════════════════════════════
    # CLEANUP (for delete / account removal)
    # ══════════════════════════════════════════
    def delete_file_metadata(self, user_id: str, original_name: str):
        """Removes a file's metadata doc when permanently deleted from vault."""
        self._db.files.delete_one({
            "user_id"       : user_id,
            "original_name" : original_name,
        })
        logger.debug(f"File metadata removed: {original_name}")

    def delete_user(self, user_id: str):
        """
        Removes a user and all their associated data.
        Called when a user opts out of Cipher Nest entirely.

        Note: Does NOT delete vault files from disk — core.py handles that.
        """
        self._db.users.delete_one({"_id": ObjectId(user_id)})
        self._db.files.delete_many({"user_id": user_id})
        # Audit logs are kept even after account deletion — for accountability.
        logger.info(f"User {user_id} and file metadata deleted from MongoDB.")

    # ══════════════════════════════════════════
    # UTILITY
    # ══════════════════════════════════════════
    def ping(self) -> bool:
        """Returns True if MongoDB connection is alive."""
        try:
            self._client.admin.command("ping")
            return True
        except Exception:
            return False

    def close(self):
        """Closes the MongoDB connection cleanly."""
        if self._client:
            self._client.close()
            logger.info("MongoDB connection closed.")


# ══════════════════════════════════════════════
# Standalone connection test
# ══════════════════════════════════════════════
if __name__ == "__main__":
    print("\n" + "═" * 55)
    print("  CIPHER NEST — audit_db.py connection test")
    print("═" * 55)

    try:
        db = AuditDB()
        alive = db.ping()
        print(f"\n  {'✓' if alive else '✗'}  MongoDB connection: {'OK' if alive else 'FAILED'}")
        print(f"  →  Database : ciphernest")
        print(f"  →  URI      : {DEFAULT_URI}")

        # ── Collections present ──
        cols = db._db.list_collection_names()
        print(f"\n  Collections: {cols if cols else '(none yet — created on first use)'}")

        db.close()

    except Exception as e:
        print(f"\n  ✗  Could not connect: {e}")
        print(f"\n  Make sure MongoDB is running:")
        print(f"    mongod --dbpath /data/db")
        print(f"\n  Or update DEFAULT_URI in audit_db.py for Atlas/Docker.\n")
