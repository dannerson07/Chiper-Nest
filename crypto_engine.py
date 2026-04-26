"""
╔══════════════════════════════════════════════════════════════╗
║           CIPHER NEST — Module 1: crypto_engine.py          ║
║      Core encryption/decryption engine using Fernet + PBKDF2 ║
║      v3 — Vault-aware, deletes original, status field        ║
╚══════════════════════════════════════════════════════════════╝

Responsibilities:
  - Derive a Fernet key from a user password using PBKDF2-HMAC-SHA256
  - Encrypt files  → move to user's vault subfolder, delete original
  - Decrypt files  → restore to original location, delete .enc from vault
  - Open files     → temp decrypt to staging area, re-encrypt after use
  - Manage salt    (generate, save, load)
  - Return MongoDB-ready result dicts from every operation

Vault structure:
  cipher_nest_vault/
    <user_id>/
      salary.pdf.enc
      salary.pdf.enc.salt
      ...

Result dict schema:
  {
      "success"          : bool,
      "action"           : "encrypt" | "decrypt" | "open" | "relock",
      "status"           : "vaulted" | "exported" | "temp_out" | "deleted",
      "user_id"          : str | None,
      "original_name"    : str,
      "input_path"       : str,
      "output_path"      : str,
      "salt_path"        : str | None,
      "file_size_bytes"  : int,
      "file_hash_sha256" : str,
      "timestamp"        : str,           # ISO-8601 UTC
      "error"            : str | None,
  }

Standalone usage:
  python crypto_engine.py --action encrypt --file secret.txt --password mypass --user-id abc123
  python crypto_engine.py --action decrypt --file secret.txt.enc --password mypass --user-id abc123
  python crypto_engine.py --action open    --file secret.txt.enc --password mypass --user-id abc123

Importable usage:
  from crypto_engine import CryptoEngine
  engine = CryptoEngine(password="mypass", user_id="abc123")
  result = engine.encrypt_file("salary.pdf")   # → vault, original deleted
  result = engine.decrypt_file("salary.pdf.enc")  # → restored, .enc deleted
  result = engine.open_file("salary.pdf.enc")  # → temp decrypt, returns temp path
  engine.relock_file(result["output_path"])    # → re-encrypt after use
"""

import os
import argparse
import hashlib
import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# ─────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("crypto_engine")

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
SALT_SIZE         = 16
PBKDF2_ITERATIONS = 390_000
ENC_EXTENSION     = ".enc"
SALT_EXTENSION    = ".salt"

# Vault root — sits next to this file by default.
# auth_cli.py can override by passing vault_root to CryptoEngine().
VAULT_ROOT = Path(__file__).parent / "cipher_nest_vault"

# Temp staging area for "open" command
TEMP_DIR   = Path(__file__).parent / "cipher_nest_temp"


# ══════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════
def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _build_result(
    success: bool,
    action: str,
    status: str,
    original_name: str,
    input_path: str,
    output_path: str,
    file_size_bytes: int,
    file_hash_sha256: str,
    salt_path=None,
    error=None,
    user_id=None,
) -> dict:
    """
    Standardised MongoDB-ready result dict.
    audit_db.py can insert this directly as a document.

    status values:
      "vaulted"   — file is encrypted inside the vault
      "exported"  — file is decrypted and returned to user (vault entry deleted)
      "temp_out"  — file is temporarily decrypted in staging area
      "deleted"   — file permanently wiped from vault
    """
    return {
        "success"          : success,
        "action"           : action,
        "status"           : status,            # ← NEW: vault state tracking
        "user_id"          : user_id,
        "original_name"    : original_name,
        "input_path"       : input_path,
        "output_path"      : output_path,
        "salt_path"        : salt_path,
        "file_size_bytes"  : file_size_bytes,
        "file_hash_sha256" : file_hash_sha256,
        "timestamp"        : _utc_now(),
        "error"            : error,
    }


# ══════════════════════════════════════════════
# CryptoEngine Class
# ══════════════════════════════════════════════
class CryptoEngine:
    """
    Handles all encryption/decryption for Cipher Nest.

    Vault strategy (Option B):
      - encrypt_file() → moves file INTO vault, deletes original
      - decrypt_file() → restores file to original location, deletes .enc
      - open_file()    → temp decrypts to staging area for viewing/editing
      - relock_file()  → re-encrypts a temp file back into vault

    Each user gets their own vault subfolder: cipher_nest_vault/<user_id>/
    No key is ever stored on disk — derived fresh from password + salt each time.
    """

    def __init__(self, password: str, user_id: str = None, vault_root: Path = None):
        """
        Args:
            password   : User's plaintext password (used for key derivation).
            user_id    : MongoDB user _id string. Sets the vault subfolder.
            vault_root : Override default vault location (useful for testing).
        """
        if not password or not isinstance(password, str):
            raise ValueError("Password must be a non-empty string.")

        self._password  = password.encode("utf-8")
        self._user_id   = user_id
        self._vault_dir = (Path(vault_root) if vault_root else VAULT_ROOT)
        self._user_vault = self._vault_dir / (user_id or "default")
        self._temp_dir   = TEMP_DIR / (user_id or "default")

        # Ensure vault and temp dirs exist
        self._user_vault.mkdir(parents=True, exist_ok=True)
        self._temp_dir.mkdir(parents=True, exist_ok=True)

    # ─────────────────────────────────────────
    # Key Derivation
    # ─────────────────────────────────────────
    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(self._password))

    # ─────────────────────────────────────────
    # Salt Management
    # ─────────────────────────────────────────
    @staticmethod
    def _generate_salt() -> bytes:
        return os.urandom(SALT_SIZE)

    @staticmethod
    def _save_salt(salt: bytes, salt_path: Path) -> None:
        salt_path.write_bytes(salt)

    @staticmethod
    def _load_salt(salt_path: Path) -> bytes:
        if not salt_path.exists():
            raise FileNotFoundError(
                f"Salt file not found: {salt_path}\n"
                "The .salt file must be in the same directory as the .enc file."
            )
        return salt_path.read_bytes()

    # ─────────────────────────────────────────
    # ENCRYPT — import into vault, delete original
    # ─────────────────────────────────────────
    def encrypt_file(self, input_path, restore_path: str = None) -> dict:
        """
        Encrypts a file and moves it into the user's vault.
        Original file is deleted ONLY after .enc is successfully written.

        Args:
            input_path   : Path to the plaintext file (anywhere on disk).
            restore_path : (Optional) Original path string — stored in MongoDB
                           so decrypt_file() knows where to restore the file.
                           Defaults to input_path if not provided.

        Returns:
            MongoDB-ready dict with status="vaulted".
        """
        input_path   = Path(input_path).resolve()
        restore_path = restore_path or str(input_path)

        # ── Validation ──
        if not input_path.exists():
            raise FileNotFoundError(f"File not found: {input_path}")
        if not input_path.is_file():
            raise ValueError(f"Not a file: {input_path}")
        if input_path.suffix == ENC_EXTENSION:
            raise ValueError("Already encrypted (.enc). Decrypt first.")

        # ── Output paths (inside user's vault) ──
        output_path = self._user_vault / (input_path.name + ENC_EXTENSION)
        salt_path   = self._user_vault / (input_path.name + ENC_EXTENSION + SALT_EXTENSION)

        # ── Read plaintext + hash BEFORE encryption ──
        plaintext = input_path.read_bytes()
        file_hash = _sha256_of_bytes(plaintext)
        file_size = len(plaintext)

        # ── Encrypt ──
        logger.info(f"Encrypting: {input_path.name} → vault")
        salt       = self._generate_salt()
        key        = self._derive_key(salt)
        fernet     = Fernet(key)
        ciphertext = fernet.encrypt(plaintext)

        # ── Write .enc first, THEN delete original ──
        output_path.write_bytes(ciphertext)
        self._save_salt(salt, salt_path)

        # ── Safe to delete original now ──
        input_path.unlink()
        logger.info(f"✓ Vaulted → {output_path.name} | Original deleted.")

        return _build_result(
            success          = True,
            action           = "encrypt",
            status           = "vaulted",           # ← file is now in vault
            user_id          = self._user_id,
            original_name    = input_path.name,
            input_path       = str(input_path),     # original location (now deleted)
            output_path      = str(output_path),    # vault location
            salt_path        = str(salt_path),
            file_size_bytes  = file_size,
            file_hash_sha256 = file_hash,
        )

    # ─────────────────────────────────────────
    # DECRYPT — export from vault, restore original
    # ─────────────────────────────────────────
    def decrypt_file(self, enc_filename: str, restore_dir=None) -> dict:
        """
        Decrypts a file from the vault and restores it to its original location.
        The .enc and .salt files are deleted from the vault after successful restore.

        Args:
            enc_filename : Just the filename (e.g. "salary.pdf.enc"),
                           looked up inside the user's vault.
            restore_dir  : (Optional) Directory to restore to.
                           Defaults to current working directory.

        Returns:
            MongoDB-ready dict with status="exported".
        """
        enc_path  = self._user_vault / enc_filename
        salt_path = self._user_vault / (enc_filename + SALT_EXTENSION)

        # ── Validation ──
        if not enc_path.exists():
            raise FileNotFoundError(f"File not in vault: {enc_filename}")
        if enc_path.suffix != ENC_EXTENSION:
            raise ValueError(f"Not an encrypted file: {enc_filename}")

        original_name = enc_path.stem                       # strip .enc
        out_dir       = Path(restore_dir).resolve() if restore_dir else Path.cwd()
        out_dir.mkdir(parents=True, exist_ok=True)
        output_path   = out_dir / original_name

        # ── Decrypt ──
        logger.info(f"Decrypting: {enc_filename} → {out_dir}")
        salt       = self._load_salt(salt_path)
        key        = self._derive_key(salt)
        fernet     = Fernet(key)
        ciphertext = enc_path.read_bytes()

        try:
            plaintext = fernet.decrypt(ciphertext)
        except InvalidToken:
            raise ValueError(
                "Decryption failed — wrong password or corrupted file."
            )

        output_path.write_bytes(plaintext)

        # ── Remove from vault after successful restore ──
        enc_path.unlink()
        if salt_path.exists():
            salt_path.unlink()
        logger.info(f"✓ Exported → {output_path} | Vault entry deleted.")

        file_hash = _sha256_of_bytes(plaintext)
        file_size = len(plaintext)

        return _build_result(
            success          = True,
            action           = "decrypt",
            status           = "exported",          # ← file is back with user
            user_id          = self._user_id,
            original_name    = original_name,
            input_path       = str(enc_path),
            output_path      = str(output_path),
            salt_path        = None,
            file_size_bytes  = file_size,
            file_hash_sha256 = file_hash,
        )

    # ─────────────────────────────────────────
    # OPEN — temp decrypt, keep vault intact
    # ─────────────────────────────────────────
    def open_file(self, enc_filename: str) -> dict:
        """
        Temporarily decrypts a file to the staging area for viewing/editing.
        The .enc stays in the vault — call relock_file() when done.

        Flow:
          open_file("salary.pdf.enc")
            → salary.pdf appears in cipher_nest_temp/<user_id>/
            → .enc stays in vault
          [user reads/edits the temp file]
          relock_file("salary.pdf")
            → re-encrypts temp file → vault
            → temp file deleted

        Returns:
            MongoDB-ready dict with status="temp_out".
            output_path = temp file location (pass this to relock_file).
        """
        enc_path  = self._user_vault / enc_filename
        salt_path = self._user_vault / (enc_filename + SALT_EXTENSION)

        if not enc_path.exists():
            raise FileNotFoundError(f"File not in vault: {enc_filename}")

        original_name = enc_path.stem
        temp_path     = self._temp_dir / original_name

        # ── Decrypt to temp ──
        logger.info(f"Temp-decrypting: {enc_filename} → staging")
        salt       = self._load_salt(salt_path)
        key        = self._derive_key(salt)
        fernet     = Fernet(key)
        ciphertext = enc_path.read_bytes()

        try:
            plaintext = fernet.decrypt(ciphertext)
        except InvalidToken:
            raise ValueError("Decryption failed — wrong password or corrupted file.")

        temp_path.write_bytes(plaintext)

        file_hash = _sha256_of_bytes(plaintext)
        file_size = len(plaintext)

        logger.info(f"✓ Temp file ready → {temp_path}")
        logger.info(f"  Call relock_file('{original_name}') when done.")

        return _build_result(
            success          = True,
            action           = "open",
            status           = "temp_out",          # ← file is temporarily outside vault
            user_id          = self._user_id,
            original_name    = original_name,
            input_path       = str(enc_path),
            output_path      = str(temp_path),      # ← pass this to relock_file()
            salt_path        = str(salt_path),
            file_size_bytes  = file_size,
            file_hash_sha256 = file_hash,            # ← hash BEFORE any edits
        )

    # ─────────────────────────────────────────
    # RELOCK — re-encrypt temp file back to vault
    # ─────────────────────────────────────────
    def relock_file(self, temp_filename: str, original_hash: str = None) -> dict:
        """
        Re-encrypts a temp file back into the vault and deletes the temp copy.
        Called after open_file() when the user is done viewing/editing.

        Args:
            temp_filename : Just the filename in the temp dir (e.g. "salary.pdf").
            original_hash : (Optional) SHA256 from the open_file() result.
                            If provided, warns if the file was modified.

        Returns:
            MongoDB-ready dict with status="vaulted".
        """
        temp_path = self._temp_dir / temp_filename

        if not temp_path.exists():
            raise FileNotFoundError(f"Temp file not found: {temp_filename}")

        # ── Check if file was modified during temp_out ──
        plaintext    = temp_path.read_bytes()
        current_hash = _sha256_of_bytes(plaintext)

        if original_hash and current_hash != original_hash:
            logger.info(f"📝 File was modified during open — re-encrypting updated version.")
        elif original_hash:
            logger.info(f"File unchanged — re-encrypting as-is.")

        # ── Re-encrypt into vault ──
        output_path = self._user_vault / (temp_filename + ENC_EXTENSION)
        salt_path   = self._user_vault / (temp_filename + ENC_EXTENSION + SALT_EXTENSION)

        salt       = self._generate_salt()
        key        = self._derive_key(salt)
        fernet     = Fernet(key)
        ciphertext = fernet.encrypt(plaintext)

        output_path.write_bytes(ciphertext)
        self._save_salt(salt, salt_path)

        # ── Delete temp file ──
        temp_path.unlink()
        logger.info(f"✓ Relocked → {output_path.name} | Temp file deleted.")

        return _build_result(
            success          = True,
            action           = "relock",
            status           = "vaulted",           # ← back in vault
            user_id          = self._user_id,
            original_name    = temp_filename,
            input_path       = str(temp_path),
            output_path      = str(output_path),
            salt_path        = str(salt_path),
            file_size_bytes  = len(plaintext),
            file_hash_sha256 = current_hash,
        )

    # ─────────────────────────────────────────
    # Verify password (no output written)
    # ─────────────────────────────────────────
    def verify_can_decrypt(self, enc_filename: str) -> bool:
        """
        Test-decrypts to verify password is correct WITHOUT writing output.
        Called by auth_cli.py to validate credentials.
        """
        enc_path  = self._user_vault / enc_filename
        salt_path = self._user_vault / (enc_filename + SALT_EXTENSION)

        try:
            salt       = self._load_salt(salt_path)
            key        = self._derive_key(salt)
            fernet     = Fernet(key)
            ciphertext = enc_path.read_bytes()
            fernet.decrypt(ciphertext)
            return True
        except (InvalidToken, FileNotFoundError):
            return False

    # ─────────────────────────────────────────
    # Integrity check
    # ─────────────────────────────────────────
    @staticmethod
    def verify_file_integrity(file_path, expected_hash: str) -> bool:
        """
        Compares SHA256 of a file on disk against the hash stored in MongoDB.
        Used after decrypt/open to confirm file wasn't tampered with.
        """
        file_path   = Path(file_path).resolve()
        actual_hash = _sha256_of_bytes(file_path.read_bytes())
        match       = actual_hash == expected_hash

        if match:
            logger.info(f"✓ Integrity verified: {file_path.name}")
        else:
            logger.warning(f"⚠ Integrity FAILED: {file_path.name} — possible tampering!")

        return match

    # ─────────────────────────────────────────
    # List vault contents
    # ─────────────────────────────────────────
    def list_vault(self) -> list:
        """
        Returns a list of encrypted filenames in the user's vault.
        Used by auth_cli.py to display available files.
        """
        return [
            f.name for f in self._user_vault.iterdir()
            if f.suffix == ENC_EXTENSION
        ]


# ══════════════════════════════════════════════
# Standalone CLI
# ══════════════════════════════════════════════
def _build_parser():
    parser = argparse.ArgumentParser(
        prog="crypto_engine",
        description="Cipher Nest — Encryption Engine (Module 1/3)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python crypto_engine.py --action encrypt --file notes.txt   --password s3cr3t --user-id abc123\n"
            "  python crypto_engine.py --action decrypt --file notes.txt.enc --password s3cr3t --user-id abc123\n"
            "  python crypto_engine.py --action open    --file notes.txt.enc --password s3cr3t --user-id abc123\n"
            "  python crypto_engine.py --action list                         --password s3cr3t --user-id abc123\n"
        )
    )
    parser.add_argument("--action",      required=True, choices=["encrypt", "decrypt", "open", "relock", "list", "verify"])
    parser.add_argument("--file",        default=None,  help="Target filename")
    parser.add_argument("--password",    required=True, help="Your password")
    parser.add_argument("--user-id",     required=True, help="Your user ID (from MongoDB)")
    parser.add_argument("--restore-dir", default=None,  help="Where to restore file on decrypt (optional)")
    parser.add_argument("--hash",        default=None,  help="Expected SHA256 for verify/relock")
    return parser


def main():
    parser = _build_parser()
    args   = parser.parse_args()

    engine = CryptoEngine(password=args.password, user_id=args.user_id)

    try:
        if args.action == "list":
            files = engine.list_vault()
            print(f"\n📦 Vault contents for user '{args.user_id}':")
            if files:
                for f in files:
                    print(f"   • {f}")
            else:
                print("   (empty)")
            return

        if not args.file:
            parser.error("--file is required for this action.")

        if args.action == "encrypt":
            result = engine.encrypt_file(args.file)
        elif args.action == "decrypt":
            result = engine.decrypt_file(args.file, args.restore_dir)
        elif args.action == "open":
            result = engine.open_file(args.file)
        elif args.action == "relock":
            result = engine.relock_file(args.file, args.hash)
        elif args.action == "verify":
            if not args.hash:
                parser.error("--hash is required for verify.")
            match = CryptoEngine.verify_file_integrity(args.file, args.hash)
            print(f"\n{'✅ MATCH' if match else '❌ MISMATCH'}")
            return

        # ── Print MongoDB-ready result ──
        print(f"\n{'✅' if result['success'] else '❌'}  [{result['action'].upper()}]  status={result['status']}")
        print(f"  original_name    : {result['original_name']}")
        print(f"  input_path       : {result['input_path']}")
        print(f"  output_path      : {result['output_path']}")
        if result['salt_path']:
            print(f"  salt_path        : {result['salt_path']}")
        print(f"  file_size_bytes  : {result['file_size_bytes']}")
        print(f"  file_hash_sha256 : {result['file_hash_sha256']}")
        print(f"  timestamp        : {result['timestamp']}")
        print(f"  user_id          : {result['user_id']}")
        print(f"\n  ↳ Ready to insert into MongoDB as audit log.")

    except (FileNotFoundError, ValueError) as e:
        logger.error(str(e))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
