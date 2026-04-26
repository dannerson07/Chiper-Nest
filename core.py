"""
╔══════════════════════════════════════════════════════════════╗
║             CIPHER NEST — Module 2a: core.py                ║
║         Pure logic layer — authentication + vault ops        ║
║         No input(), no print(), no CLI, no GUI               ║
║         Works identically under CLI and Tkinter              ║
╚══════════════════════════════════════════════════════════════╝

Responsibilities:
  - User registration and login (bcrypt)
  - Session management (in-memory)
  - Vault operations: encrypt, decrypt, open, relock, delete, list
  - Bridges crypto_engine.py ↔ audit_db.py
  - Returns clean result dicts — caller decides how to display them

This module has ZERO knowledge of:
  - How results are displayed (CLI print / Tkinter label / web response)
  - How input is collected (input() / Entry widget / API request)

Usage from cli.py:
  from core import CipherNestCore
  app = CipherNestCore()
  result = app.register("karthik", "secret123")
  result = app.login("karthik", "secret123")
  result = app.encrypt_file("/home/karthik/salary.pdf")
  result = app.decrypt_file("salary.pdf.enc")
  result = app.open_file("salary.pdf.enc")
  result = app.relock_file("salary.pdf")
  result = app.logout()

Usage from gui.py (future Tkinter):
  from core import CipherNestCore
  app = CipherNestCore()          # exact same calls
  result = app.login("karthik", "secret123")
  # display result however Tkinter needs — core doesn't care
"""

import logging
from datetime import datetime, timezone
from pathlib import Path

import bcrypt

from crypto_engine import CryptoEngine
# audit_db will be imported once Module 3 is built.
# For now, a placeholder is used so core.py works standalone.
try:
    from audit_db import AuditDB
    _AUDIT_AVAILABLE = True
except ImportError:
    _AUDIT_AVAILABLE = False

# ─────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("core")


# ══════════════════════════════════════════════
# Session — in-memory only, never written to disk
# ══════════════════════════════════════════════
class Session:
    """
    Holds the currently logged-in user's data.
    Lives in memory only — cleared on logout or app exit.
    Password is kept in memory so CryptoEngine can derive
    the Fernet key on demand without asking the user again.
    """

    def __init__(self):
        self.user_id   = None   # MongoDB _id string
        self.username  = None
        self._password = None   # plaintext — in memory only, never persisted
        self.active    = False
        self.login_time = None

    def start(self, user_id: str, username: str, password: str):
        self.user_id    = user_id
        self.username   = username
        self._password  = password
        self.active     = True
        self.login_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        logger.info(f"Session started — user: {username}")

    def end(self):
        self.user_id    = None
        self.username   = None
        self._password  = None      # wipe password from memory
        self.active     = False
        self.login_time = None
        logger.info("Session ended — memory cleared.")

    @property
    def password(self):
        return self._password

    def require_active(self):
        """Raises if no user is logged in. Call at the start of any vault op."""
        if not self.active:
            raise PermissionError("No active session. Please login first.")


# ══════════════════════════════════════════════
# Result builder
# ══════════════════════════════════════════════
def _result(success: bool, action: str, message: str, data: dict = None) -> dict:
    """
    Standardised result dict returned by every core.py method.
    cli.py and gui.py read this to decide what to show the user.

    Shape:
      {
          "success" : bool,
          "action"  : str,    e.g. "register", "login", "encrypt"
          "message" : str,    human-readable summary
          "data"    : dict,   operation-specific payload (or None)
      }
    """
    return {
        "success" : success,
        "action"  : action,
        "message" : message,
        "data"    : data or {},
    }


# ══════════════════════════════════════════════
# CipherNestCore
# ══════════════════════════════════════════════
class CipherNestCore:
    """
    The single entry point for all Cipher Nest operations.

    Both cli.py and gui.py create ONE instance of this class
    and call its methods. They never touch CryptoEngine or
    AuditDB directly — core.py orchestrates everything.

    Architecture:
      cli.py / gui.py
           ↓  calls
       CipherNestCore          ← you are here
           ↓  uses             ↓  uses
      CryptoEngine          AuditDB
      (encryption)          (MongoDB)
    """

    def __init__(self, db_uri: str = None, vault_root: Path = None):
        """
        Args:
            db_uri     : MongoDB connection URI (passed to AuditDB).
                         If None, AuditDB uses its default URI.
            vault_root : Override vault folder location (useful for testing).
        """
        self.session    = Session()
        self._vault_root = vault_root
        self._engine    = None      # created fresh on login with user's password

        # AuditDB — graceful degradation if Module 3 not yet built
        if _AUDIT_AVAILABLE:
            self._db = AuditDB(uri=db_uri)
        else:
            self._db = None
            logger.warning("audit_db.py not found — running without MongoDB logging.")

    # ─────────────────────────────────────────
    # Internal: get or build CryptoEngine
    # ─────────────────────────────────────────
    def _get_engine(self) -> CryptoEngine:
        """
        Returns the CryptoEngine for the current session.
        Built once on login, reused for the session duration.
        """
        self.session.require_active()
        if self._engine is None:
            self._engine = CryptoEngine(
                password   = self.session.password,
                user_id    = self.session.user_id,
                vault_root = self._vault_root,
            )
        return self._engine

    # ─────────────────────────────────────────
    # Internal: log to MongoDB (safe — won't crash if DB unavailable)
    # ─────────────────────────────────────────
    def _log(self, operation_result: dict):
        """Sends a crypto_engine result dict to AuditDB. Fails silently."""
        if self._db:
            try:
                self._db.log_operation(operation_result)
            except Exception as e:
                logger.warning(f"Audit log failed (non-critical): {e}")

    # ══════════════════════════════════════════
    # AUTH — Register
    # ══════════════════════════════════════════
    def register(self, username: str, password: str) -> dict:
        """
        Creates a new user account.

        - Validates username and password strength.
        - Hashes password with bcrypt.
        - Saves user to MongoDB via AuditDB.
        - Does NOT auto-login (user must call login() after).

        Args:
            username : Desired username (3–32 chars, alphanumeric + underscore).
            password : Plaintext password (min 8 chars).

        Returns:
            result dict — success=True if registered, False if username taken or invalid.
        """
        action = "register"

        # ── Validate username ──
        if not username or not isinstance(username, str):
            return _result(False, action, "Username cannot be empty.")
        username = username.strip()
        if len(username) < 3 or len(username) > 32:
            return _result(False, action, "Username must be 3–32 characters.")
        if not all(c.isalnum() or c == "_" for c in username):
            return _result(False, action, "Username can only contain letters, numbers, and underscores.")

        # ── Validate password ──
        if not password or len(password) < 8:
            return _result(False, action, "Password must be at least 8 characters.")

        # ── Check if username already exists ──
        if self._db and self._db.user_exists(username):
            return _result(False, action, f"Username '{username}' is already taken.")

        # ── Hash password with bcrypt ──
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt(rounds=12)       # 12 rounds = OWASP recommended
        ).decode("utf-8")                   # store as string in MongoDB

        # ── Save to MongoDB ──
        user_doc = {
            "username"      : username,
            "password_hash" : password_hash,
            "created_at"    : datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "vault_files"   : [],           # list of encrypted filenames
        }

        user_id = None
        if self._db:
            user_id = self._db.create_user(user_doc)
        else:
            # No DB — generate a local placeholder ID for standalone testing
            import hashlib
            user_id = hashlib.md5(username.encode()).hexdigest()[:12]

        logger.info(f"Registered user: {username} (id={user_id})")

        return _result(
            True, action,
            f"Account created successfully. Welcome, {username}!",
            data={"user_id": user_id, "username": username}
        )

    # ══════════════════════════════════════════
    # AUTH — Login
    # ══════════════════════════════════════════
    def login(self, username: str, password: str) -> dict:
        """
        Authenticates a user and starts a session.

        - Fetches user record from MongoDB.
        - Verifies password against bcrypt hash.
        - Starts in-memory session (user_id + password stored).
        - Builds CryptoEngine for this session.

        Args:
            username : Registered username.
            password : Plaintext password.

        Returns:
            result dict — success=True if credentials valid, False otherwise.
        """
        action = "login"

        if self.session.active:
            return _result(False, action, f"Already logged in as '{self.session.username}'. Logout first.")

        # ── Fetch user from MongoDB ──
        user_doc = None
        if self._db:
            user_doc = self._db.get_user(username)

        if not user_doc:
            # Timing-safe: still run bcrypt even on miss to prevent user enumeration
            bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
            return _result(False, action, "Invalid username or password.")

        # ── Verify password ──
        password_match = bcrypt.checkpw(
            password.encode("utf-8"),
            user_doc["password_hash"].encode("utf-8")
        )

        if not password_match:
            return _result(False, action, "Invalid username or password.")

        # ── Start session ──
        user_id = str(user_doc["_id"])
        self.session.start(user_id, username, password)

        # ── Build CryptoEngine for this session ──
        self._engine = CryptoEngine(
            password   = password,
            user_id    = user_id,
            vault_root = self._vault_root,
        )

        logger.info(f"Login successful: {username}")

        return _result(
            True, action,
            f"Welcome back, {username}!",
            data={
                "user_id"    : user_id,
                "username"   : username,
                "login_time" : self.session.login_time,
            }
        )

    # ══════════════════════════════════════════
    # AUTH — Logout
    # ══════════════════════════════════════════
    def logout(self) -> dict:
        """
        Ends the current session and wipes password from memory.

        Returns:
            result dict — always success=True.
        """
        action = "logout"
        if not self.session.active:
            return _result(False, action, "No active session to logout from.")

        username = self.session.username
        self.session.end()
        self._engine = None         # wipe engine (holds password reference)

        return _result(True, action, f"Goodbye, {username}. Session cleared.")

    # ══════════════════════════════════════════
    # VAULT — Encrypt (import file into vault)
    # ══════════════════════════════════════════
    def encrypt_file(self, file_path: str) -> dict:
        """
        Imports a file into the vault.
        Original is deleted after successful encryption.

        Args:
            file_path : Full path to the plaintext file.

        Returns:
            result dict with data = crypto_engine result (MongoDB-ready).
        """
        action = "encrypt"
        self.session.require_active()

        try:
            op_result = self._get_engine().encrypt_file(
                input_path = file_path,
            )
            op_result["user_id"] = self.session.user_id
            self._log(op_result)

            return _result(
                True, action,
                f"'{op_result['original_name']}' encrypted and vaulted. Original deleted.",
                data=op_result
            )

        except (FileNotFoundError, ValueError) as e:
            return _result(False, action, str(e))

    # ══════════════════════════════════════════
    # VAULT — Decrypt (export file from vault)
    # ══════════════════════════════════════════
    def decrypt_file(self, enc_filename: str, restore_dir: str = None) -> dict:
        """
        Exports a file from the vault back to disk.
        .enc and .salt are deleted from vault after successful restore.

        Args:
            enc_filename : Filename inside vault (e.g. "salary.pdf.enc").
            restore_dir  : Where to restore the file. Defaults to cwd.

        Returns:
            result dict with data = crypto_engine result (MongoDB-ready).
        """
        action = "decrypt"
        self.session.require_active()

        try:
            op_result = self._get_engine().decrypt_file(
                enc_filename = enc_filename,
                restore_dir  = restore_dir,
            )
            op_result["user_id"] = self.session.user_id
            self._log(op_result)

            return _result(
                True, action,
                f"'{op_result['original_name']}' restored to {op_result['output_path']}.",
                data=op_result
            )

        except (FileNotFoundError, ValueError) as e:
            return _result(False, action, str(e))

    # ══════════════════════════════════════════
    # VAULT — Open (temp decrypt for viewing)
    # ══════════════════════════════════════════
    def open_file(self, enc_filename: str) -> dict:
        """
        Temporarily decrypts a file to the staging area.
        Call relock_file() when done — file goes back to vault.

        Args:
            enc_filename : Filename inside vault (e.g. "notes.txt.enc").

        Returns:
            result dict — data includes temp file path and original hash.
        """
        action = "open"
        self.session.require_active()

        try:
            op_result = self._get_engine().open_file(
                enc_filename = enc_filename,
            )
            op_result["user_id"] = self.session.user_id
            self._log(op_result)

            return _result(
                True, action,
                f"'{op_result['original_name']}' is ready at: {op_result['output_path']}\n"
                f"Call relock when done.",
                data=op_result
            )

        except (FileNotFoundError, ValueError) as e:
            return _result(False, action, str(e))

    # ══════════════════════════════════════════
    # VAULT — Relock (re-encrypt after open)
    # ══════════════════════════════════════════
    def relock_file(self, temp_filename: str, original_hash: str = None) -> dict:
        """
        Re-encrypts a temp file back into the vault.
        Deletes the temp copy when done.

        Args:
            temp_filename : Filename in staging area (e.g. "notes.txt").
            original_hash : SHA256 from open_file() result — detects modifications.

        Returns:
            result dict — data includes new vault path.
        """
        action = "relock"
        self.session.require_active()

        try:
            op_result = self._get_engine().relock_file(
                temp_filename = temp_filename,
                original_hash = original_hash,
            )
            self._log(op_result)

            return _result(
                True, action,
                f"'{op_result['original_name']}' relocked into vault. Temp file deleted.",
                data=op_result
            )

        except (FileNotFoundError, ValueError) as e:
            return _result(False, action, str(e))

    # ══════════════════════════════════════════
    # VAULT — Delete permanently
    # ══════════════════════════════════════════
    def delete_file(self, enc_filename: str) -> dict:
        """
        Permanently deletes a file from the vault. No recovery possible.

        Args:
            enc_filename : Filename inside vault (e.g. "salary.pdf.enc").

        Returns:
            result dict — success=True if deleted.
        """
        action = "delete"
        self.session.require_active()

        engine   = self._get_engine()
        enc_path = engine._user_vault / enc_filename
        salt_path = engine._user_vault / (enc_filename + ".salt")

        if not enc_filename or not enc_filename.strip():
            return _result(False, action, "No filename provided.")

        if not enc_path.exists():
            return _result(False, action, f"File not found in vault: {enc_filename}")

        if not enc_path.is_file():
            return _result(False, action, f"'{enc_filename}' is not a valid file.")

        enc_path.unlink()
        if salt_path.exists() and salt_path.is_file():
            salt_path.unlink()

        # Log the deletion
        from crypto_engine import _utc_now
        op_result = {
            "success"          : True,
            "action"           : "delete",
            "status"           : "deleted",
            "user_id"          : self.session.user_id,
            "original_name"    : enc_path.stem,
            "input_path"       : str(enc_path),
            "output_path"      : None,
            "salt_path"        : None,
            "file_size_bytes"  : 0,
            "file_hash_sha256" : None,
            "timestamp"        : _utc_now(),
            "error"            : None,
        }
        self._log(op_result)

        logger.info(f"Permanently deleted: {enc_filename}")
        return _result(
            True, action,
            f"'{enc_filename}' permanently deleted from vault.",
            data=op_result
        )

    # ══════════════════════════════════════════
    # ACCOUNT — Delete (Option C: export then wipe)
    # ══════════════════════════════════════════
    def delete_account(self, password: str, export_dir: str) -> dict:
        """
        Permanently deletes the current user's account.

        Flow:
          1. Verify password (bcrypt) — prevents accidental/unauthorized deletion
          2. Decrypt all vault files → restore to export_dir
          3. Delete vault folder from disk
          4. Delete user + file metadata from MongoDB
          5. Wipe session from memory
          (Audit logs are kept permanently)

        Args:
            password   : User's plaintext password for final verification.
            export_dir : Directory where all vault files will be restored.

        Returns:
            result dict — success=True if account fully deleted.
            data includes: exported_files (list), export_dir, failed_files (list)
        """
        action = "delete_account"
        self.session.require_active()

        # ── Step 1: Verify password before doing anything destructive ──
        if self._db:
            user_doc = self._db.get_user(self.session.username)
            if not user_doc:
                return _result(False, action, "User not found in database.")

            import bcrypt as _bcrypt
            password_match = _bcrypt.checkpw(
                password.encode("utf-8"),
                user_doc["password_hash"].encode("utf-8")
            )
            if not password_match:
                return _result(False, action, "Incorrect password. Account deletion cancelled.")

        # ── Step 2: Export all vault files ──
        export_path    = Path(export_dir)
        export_path.mkdir(parents=True, exist_ok=True)

        engine         = self._get_engine()
        vault_files    = engine.list_vault()
        exported_files = []
        failed_files   = []

        logger.info(f"Exporting {len(vault_files)} file(s) before account deletion...")

        for enc_filename in vault_files:
            try:
                op_result = engine.decrypt_file(
                    enc_filename = enc_filename,
                    restore_dir  = str(export_path),
                )
                op_result["user_id"] = self.session.user_id
                self._log(op_result)
                exported_files.append(op_result["original_name"])
                logger.info(f"  Exported: {op_result['original_name']}")

            except Exception as e:
                logger.error(f"  Failed to export {enc_filename}: {e}")
                failed_files.append(enc_filename)

        # ── Step 3: Delete vault folder from disk ──
        vault_dir = engine._user_vault
        try:
            import shutil
            if vault_dir.exists():
                shutil.rmtree(vault_dir)
                logger.info(f"Vault folder deleted: {vault_dir}")
        except Exception as e:
            logger.warning(f"Could not delete vault folder: {e}")

        # ── Step 4: Delete from MongoDB ──
        if self._db:
            try:
                self._db.delete_user(self.session.user_id)
                logger.info(f"User {self.session.username} removed from MongoDB.")
            except Exception as e:
                logger.warning(f"MongoDB cleanup partial: {e}")

        # ── Step 5: Wipe session ──
        username = self.session.username
        self.session.end()
        self._engine = None

        # ── Build summary ──
        if failed_files:
            message = (
                f"Account deleted with warnings.\n"
                f"  Exported : {len(exported_files)} file(s) → {export_dir}\n"
                f"  Failed   : {len(failed_files)} file(s) could not be exported: {failed_files}"
            )
        else:
            message = (
                f"Account '{username}' fully deleted.\n"
                f"  {len(exported_files)} file(s) exported to: {export_dir}"
            )

        logger.info(f"Account deletion complete: {username}")

        return _result(
            len(failed_files) == 0,
            action,
            message,
            data={
                "username"       : username,
                "exported_files" : exported_files,
                "failed_files"   : failed_files,
                "export_dir"     : str(export_path),
            }
        )

    # ══════════════════════════════════════════
    # ACCOUNT — Delete (Option C: export first, then wipe)
    # ══════════════════════════════════════════
    def delete_account(self, password: str, export_dir: str) -> dict:
        """
        Permanently deletes the current user's account.

        Flow (Option C):
          1. Verify password (bcrypt) — prevents accidental/unauthorized deletion.
          2. Decrypt every .enc file in the vault → restore to export_dir.
          3. Delete all .enc + .salt files from vault folder.
          4. Delete vault/<user_id>/ folder.
          5. Wipe user + file metadata from MongoDB (audit logs kept).
          6. End session.

        Args:
            password   : User's plaintext password for final confirmation.
            export_dir : Directory to restore all vault files to.

        Returns:
            result dict — success=True if fully wiped.
            data includes: exported_files (list), failed_files (list).
        """
        action = "delete_account"
        self.session.require_active()

        # ── Step 1: Verify password ──
        if self._db:
            user_doc = self._db.get_user(self.session.username)
            if not user_doc:
                return _result(False, action, "User not found in database.")

            import bcrypt
            if not bcrypt.checkpw(password.encode("utf-8"),
                                  user_doc["password_hash"].encode("utf-8")):
                return _result(False, action, "Incorrect password. Account deletion cancelled.")
        else:
            # No DB — skip bcrypt check in standalone mode
            logger.warning("No DB available — skipping password verification for delete_account.")

        # ── Step 2 & 3: Export all vault files ──
        engine     = self._get_engine()
        vault_dir  = engine._user_vault
        export_dir = Path(export_dir).resolve()
        export_dir.mkdir(parents=True, exist_ok=True)

        enc_files      = [f.name for f in vault_dir.iterdir() if f.suffix == ".enc"]
        exported_files = []
        failed_files   = []

        for enc_filename in enc_files:
            try:
                op_result = engine.decrypt_file(
                    enc_filename = enc_filename,
                    restore_dir  = str(export_dir),
                )
                exported_files.append(op_result["original_name"])
                logger.info(f"Exported: {op_result['original_name']}")
            except Exception as e:
                failed_files.append({"file": enc_filename, "error": str(e)})
                logger.error(f"Failed to export {enc_filename}: {e}")

        # ── Step 4: Delete vault folder ──
        # Remove any leftover .salt files (failed decrypts may leave them)
        for leftover in vault_dir.iterdir():
            leftover.unlink()
        vault_dir.rmdir()
        logger.info(f"Vault folder deleted: {vault_dir}")

        # ── Step 5: Wipe from MongoDB ──
        if self._db:
            self._db.delete_user(
                user_id  = self.session.user_id,
                username = self.session.username,
            )

        # ── Step 6: End session ──
        username = self.session.username
        self.session.end()
        self._engine = None

        # ── Build summary ──
        if failed_files:
            message = (
                f"Account '{username}' deleted with {len(failed_files)} export failure(s). "
                f"Check failed_files in data for details."
            )
        else:
            message = (
                f"Account '{username}' fully deleted. "
                f"{len(exported_files)} file(s) exported to: {export_dir}"
            )

        return _result(
            len(failed_files) == 0,
            action,
            message,
            data={
                "username"       : username,
                "exported_files" : exported_files,
                "failed_files"   : failed_files,
                "export_dir"     : str(export_dir),
            }
        )

    # ══════════════════════════════════════════
    # VAULT — List files
    # ══════════════════════════════════════════
    def list_files(self) -> dict:
        """
        Lists all encrypted files in the current user's vault.

        Returns:
            result dict — data includes list of filenames.
        """
        action = "list"
        self.session.require_active()

        files = self._get_engine().list_vault()

        return _result(
            True, action,
            f"{len(files)} file(s) in vault.",
            data={"files": files, "count": len(files)}
        )

    # ══════════════════════════════════════════
    # VAULT — Integrity check
    # ══════════════════════════════════════════
    def check_integrity(self, file_path: str, expected_hash: str) -> dict:
        """
        Verifies a file's SHA256 against the hash stored in MongoDB.
        Used after open/decrypt to confirm no tampering.

        Args:
            file_path     : Path to the file on disk.
            expected_hash : SHA256 hex string from MongoDB audit record.

        Returns:
            result dict — success=True if hash matches.
        """
        action = "integrity_check"
        match  = CryptoEngine.verify_file_integrity(file_path, expected_hash)

        return _result(
            match, action,
            "Integrity verified — file is unchanged." if match
            else "⚠ Integrity check FAILED — file may have been tampered with!",
            data={"match": match, "file_path": file_path}
        )

    # ══════════════════════════════════════════
    # ACCOUNT — Delete (Option C: export then wipe)
    # ══════════════════════════════════════════
    def delete_account(self, password: str, export_dir: str) -> dict:
        """
        Permanently deletes the current user's account.

        Flow:
          1. Verify password (bcrypt) — extra confirmation gate
          2. Decrypt + export every vaulted file to export_dir
          3. Delete all .enc and .salt files from vault folder
          4. Delete vault/<user_id>/ folder
          5. Remove user + file metadata from MongoDB
             (audit logs are KEPT for accountability)
          6. Wipe session from memory

        Args:
            password   : User's plaintext password for final verification.
            export_dir : Directory to restore all vault files into.

        Returns:
            result dict — success=True if fully completed.
            data includes list of restored files and any failures.
        """
        action = "delete_account"
        self.session.require_active()

        # ── Step 1: Verify password before doing anything destructive ──
        if self._db:
            user_doc = self._db.get_user(self.session.username)
            if not user_doc:
                return _result(False, action, "User record not found in database.")

            import bcrypt as _bcrypt
            password_match = _bcrypt.checkpw(
                password.encode("utf-8"),
                user_doc["password_hash"].encode("utf-8")
            )
            if not password_match:
                return _result(False, action, "Incorrect password. Account deletion cancelled.")

        # ── Step 2: Validate + prepare export directory ──
        export_dir = Path(export_dir).resolve()

        if export_dir.exists() and not export_dir.is_dir():
            return _result(
                False, action,
                f"'{export_dir}' is a file, not a directory. "
                "Please provide a valid folder path (e.g. C:\\Users\\Jerush\\Desktop\\exports)"
            )

        export_dir.mkdir(parents=True, exist_ok=True)

        # ── Step 3: Export all vault files ──
        engine      = self._get_engine()
        vault_files = engine.list_vault()

        restored  = []      # successfully exported filenames
        failed    = []      # filenames that couldn't be exported

        for enc_filename in vault_files:
            try:
                op_result = engine.decrypt_file(
                    enc_filename = enc_filename,
                    restore_dir  = str(export_dir),
                )
                op_result["user_id"] = self.session.user_id
                self._log(op_result)
                restored.append(op_result["original_name"])
                logger.info(f"Exported: {op_result['original_name']} → {export_dir}")

            except Exception as e:
                failed.append(enc_filename)
                logger.error(f"Failed to export {enc_filename}: {e}")

        # ── Step 3 & 4: Delete vault folder ──
        user_vault = engine._user_vault
        try:
            import shutil
            if user_vault.exists():
                shutil.rmtree(user_vault)
                logger.info(f"Vault folder deleted: {user_vault}")
        except Exception as e:
            logger.error(f"Could not delete vault folder: {e}")

        # ── Step 5: Wipe from MongoDB ──
        user_id  = self.session.user_id
        username = self.session.username

        if self._db:
            self._db.delete_user(user_id)

        # ── Step 6: Wipe session ──
        self.session.end()
        self._engine = None

        # ── Build summary ──
        if failed:
            message = (
                f"Account deleted with warnings. "
                f"{len(restored)} file(s) exported, {len(failed)} failed. "
                f"Files saved to: {export_dir}"
            )
        else:
            message = (
                f"Account fully deleted. "
                f"{len(restored)} file(s) exported to: {export_dir}"
            )

        logger.info(f"Account deleted: {username}")

        return _result(
            True, action,
            message,
            data={
                "username"     : username,
                "export_dir"   : str(export_dir),
                "restored"     : restored,
                "failed"       : failed,
                "total_files"  : len(vault_files),
            }
        )

    # ══════════════════════════════════════════
    # UTIL — Session info
    # ══════════════════════════════════════════
    def session_info(self) -> dict:
        """Returns current session state. Useful for GUI status bars."""
        return {
            "active"     : self.session.active,
            "username"   : self.session.username,
            "user_id"    : self.session.user_id,
            "login_time" : self.session.login_time,
        }


# ══════════════════════════════════════════════
# Standalone test (no CLI, just raw function calls)
# ══════════════════════════════════════════════
if __name__ == "__main__":
    import tempfile
    import os

    print("\n" + "═"*55)
    print("  CIPHER NEST — core.py standalone test")
    print("═"*55)

    app = CipherNestCore()

    # ── Register ──
    r = app.register("karthik", "secret123")
    print(f"\n[REGISTER] {r['message']}")

    # ── Login ──
    r = app.login("karthik", "secret123")
    print(f"[LOGIN]    {r['message']}")

    # ── Create a test file ──
    test_file = Path(tempfile.mktemp(suffix=".txt"))
    test_file.write_text("This is a secret document. Handle with care.")
    print(f"\n[TEST FILE] Created: {test_file}")

    # ── Encrypt ──
    r = app.encrypt_file(str(test_file))
    print(f"[ENCRYPT]  {r['message']}")
    enc_filename = Path(r['data']['output_path']).name if r['success'] else None

    # ── List ──
    r = app.list_files()
    print(f"[LIST]     {r['message']} → {r['data']['files']}")

    # ── Open ──
    if enc_filename:
        r = app.open_file(enc_filename)
        print(f"[OPEN]     {r['message']}")
        original_hash = r['data']['file_hash_sha256'] if r['success'] else None
        temp_name     = Path(r['data']['output_path']).name if r['success'] else None

        # ── Relock ──
        if temp_name:
            r = app.relock_file(temp_name, original_hash)
            print(f"[RELOCK]   {r['message']}")

    # ── Logout ──
    r = app.logout()
    print(f"[LOGOUT]   {r['message']}")

    print("\n" + "═"*55)
    print("  All operations completed. Check vault folder.")
    print("═"*55 + "\n")
