"""
╔══════════════════════════════════════════════════════════════╗
║              CIPHER NEST — Module 2b: cli.py                ║
║         CLI interface — thin wrapper over core.py            ║
║         All logic lives in core.py. This file only handles: ║
║           - input() / getpass                                ║
║           - print() / display formatting                     ║
║           - Menu navigation                                  ║
╚══════════════════════════════════════════════════════════════╝

Run:
  python cli.py
"""

import getpass
import os
import sys
from pathlib import Path

from core import CipherNestCore

# ─────────────────────────────────────────────
# Terminal colours (graceful fallback on Windows)
# ─────────────────────────────────────────────
try:
    import colorama
    colorama.init(autoreset=True)
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"
except ImportError:
    GREEN = RED = YELLOW = CYAN = BOLD = DIM = RESET = ""


# ══════════════════════════════════════════════
# Display helpers
# ══════════════════════════════════════════════
def _clear():
    os.system("cls" if os.name == "nt" else "clear")


def _banner():
    print(f"""
{CYAN}{BOLD}
  ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗     ███╗   ██╗███████╗███████╗████████╗
 ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗    ████╗  ██║██╔════╝██╔════╝╚══██╔══╝
 ██║     ██║██████╔╝███████║█████╗  ██████╔╝    ██╔██╗ ██║█████╗  ███████╗   ██║
 ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗    ██║╚██╗██║██╔══╝  ╚════██║   ██║
 ╚██████╗██║██║     ██║  ██║███████╗██║  ██║    ██║ ╚████║███████╗███████║   ██║
  ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝  ╚═══╝╚══════╝╚══════╝   ╚═╝
{RESET}{CYAN}                     S e c u r e   F i l e   V a u l t{RESET}
{DIM}  ──────────────────────────────────────────────────────────────────────────{RESET}
""")


def _ok(msg: str):
    print(f"\n  {GREEN}✓{RESET}  {msg}")


def _err(msg: str):
    print(f"\n  {RED}✗{RESET}  {msg}")


def _info(msg: str):
    print(f"\n  {YELLOW}→{RESET}  {msg}")


def _divider():
    print(f"\n{DIM}  {'─' * 48}{RESET}")


def _prompt(label: str) -> str:
    return input(f"\n  {CYAN}›{RESET}  {label}: ").strip()


def _password_prompt(label: str = "Password") -> str:
    return getpass.getpass(f"\n  {CYAN}›{RESET}  {label}: ")


def _show_result(result: dict):
    """Prints a core.py result dict in a user-friendly way."""
    if result["success"]:
        _ok(result["message"])
    else:
        _err(result["message"])


def _press_enter():
    input(f"\n  {DIM}Press Enter to continue...{RESET}")


# ══════════════════════════════════════════════
# CipherNestCLI
# ══════════════════════════════════════════════
class CipherNestCLI:
    """
    Thin CLI shell over CipherNestCore.
    Handles ONLY:
      - Collecting input from the user
      - Displaying results
      - Menu navigation

    Zero business logic lives here.
    Swapping this for a Tkinter GUI = zero changes to core.py.
    """

    def __init__(self):
        self.app = CipherNestCore()

    # ══════════════════════════════════════════
    # Entry point
    # ══════════════════════════════════════════
    def run(self):
        _clear()
        _banner()
        while True:
            if self.app.session.active:
                self._vault_menu()
            else:
                self._auth_menu()

    # ══════════════════════════════════════════
    # AUTH MENU — shown when not logged in
    # ══════════════════════════════════════════
    def _auth_menu(self):
        print(f"\n  {BOLD}What would you like to do?{RESET}\n")
        print(f"  {CYAN}[1]{RESET}  Register")
        print(f"  {CYAN}[2]{RESET}  Login")
        print(f"  {CYAN}[0]{RESET}  Exit")
        _divider()

        choice = _prompt("Choice")

        if choice == "1":
            self._handle_register()
        elif choice == "2":
            self._handle_login()
        elif choice == "0":
            self._exit()
        else:
            _err("Invalid choice. Try again.")

    # ══════════════════════════════════════════
    # VAULT MENU — shown when logged in
    # ══════════════════════════════════════════
    def _vault_menu(self):
        info = self.app.session_info()
        print(f"\n  {DIM}Logged in as{RESET} {BOLD}{info['username']}{RESET}"
              f"  {DIM}since {info['login_time']}{RESET}\n")

        print(f"  {CYAN}[1]{RESET}  Encrypt a file   {DIM}(import into vault){RESET}")
        print(f"  {CYAN}[2]{RESET}  Decrypt a file   {DIM}(export from vault){RESET}")
        print(f"  {CYAN}[3]{RESET}  Open a file      {DIM}(temp view / edit){RESET}")
        print(f"  {CYAN}[4]{RESET}  List vault files")
        print(f"  {CYAN}[5]{RESET}  Delete a file    {DIM}(permanent){RESET}")
        print(f"  {CYAN}[6]{RESET}  View audit log")
        print(f"  {CYAN}[9]{RESET}  {RED}Delete account{RESET}   {DIM}(export files + wipe){RESET}")
        print(f"  {CYAN}[0]{RESET}  Logout")
        _divider()

        choice = _prompt("Choice")

        if choice == "1":
            self._handle_encrypt()
        elif choice == "2":
            self._handle_decrypt()
        elif choice == "3":
            self._handle_open()
        elif choice == "4":
            self._handle_list()
        elif choice == "5":
            self._handle_delete()
        elif choice == "6":
            self._handle_audit_log()
        elif choice == "9":
            self._handle_delete_account()
        elif choice == "0":
            self._handle_logout()
        else:
            _err("Invalid choice. Try again.")

    # ══════════════════════════════════════════
    # AUTH handlers
    # ══════════════════════════════════════════
    def _handle_register(self):
        _clear()
        _banner()
        print(f"  {BOLD}Create an account{RESET}\n")

        username = _prompt("Username")
        password = _password_prompt("Password (min 8 chars)")
        confirm  = _password_prompt("Confirm password")

        if password != confirm:
            _err("Passwords do not match.")
            _press_enter()
            return

        result = self.app.register(username, password)
        _show_result(result)

        if result["success"]:
            _info("You can now login with your credentials.")

        _press_enter()

    def _handle_login(self):
        _clear()
        _banner()
        print(f"  {BOLD}Login{RESET}\n")

        username = _prompt("Username")
        password = _password_prompt("Password")

        result = self.app.login(username, password)
        _show_result(result)

        if result["success"]:
            _clear()
            _banner()
        else:
            _press_enter()

    def _handle_logout(self):
        result = self.app.logout()
        _show_result(result)
        _press_enter()
        _clear()
        _banner()

    # ══════════════════════════════════════════
    # VAULT handlers
    # ══════════════════════════════════════════
    def _handle_encrypt(self):
        _clear()
        _banner()
        print(f"  {BOLD}Encrypt a file{RESET}")
        _info("The original file will be deleted after encryption.")
        print()

        file_path = _prompt("Full path to file")

        # ── Confirm before deleting original ──
        print(f"\n  {YELLOW}Are you sure? The original will be permanently deleted.{RESET}")
        confirm = _prompt("Type 'yes' to confirm").lower()

        if confirm != "yes":
            _info("Cancelled.")
            _press_enter()
            return

        result = self.app.encrypt_file(file_path)
        _show_result(result)

        if result["success"]:
            _info(f"Vault location: {result['data']['output_path']}")
            _info(f"SHA256: {result['data']['file_hash_sha256']}")

        _press_enter()

    def _handle_decrypt(self):
        _clear()
        _banner()
        print(f"  {BOLD}Decrypt a file{RESET}")
        _info("File will be restored. Vault entry will be deleted.")
        print()

        # ── Show vault contents first ──
        self._print_vault_files()

        enc_filename = _prompt("Filename to decrypt (e.g. salary.pdf.enc)")
        restore_dir  = _prompt("Restore to directory (leave blank for current folder)")
        restore_dir  = restore_dir if restore_dir else None

        result = self.app.decrypt_file(enc_filename, restore_dir)
        _show_result(result)

        if result["success"]:
            _info(f"Restored to: {result['data']['output_path']}")

        _press_enter()

    def _handle_open(self):
        _clear()
        _banner()
        print(f"  {BOLD}Open a file temporarily{RESET}")
        _info("File will be decrypted to a staging area. Relocked when done.")
        print()

        self._print_vault_files()

        enc_filename = _prompt("Filename to open (e.g. notes.txt.enc)")
        result       = self.app.open_file(enc_filename)
        _show_result(result)

        if not result["success"]:
            _press_enter()
            return

        temp_path     = result["data"]["output_path"]
        original_hash = result["data"]["file_hash_sha256"]
        temp_filename = Path(temp_path).name

        _info(f"Temp file ready: {temp_path}")
        print(f"\n  {DIM}Open it, read it, edit it. Come back here when done.{RESET}")
        _press_enter()

        # ── Relock prompt ──
        print(f"\n  {BOLD}Relock file back into vault?{RESET}")
        print(f"  {CYAN}[1]{RESET}  Yes — relock now")
        print(f"  {CYAN}[2]{RESET}  No  — leave it (you can relock later)")
        _divider()

        choice = _prompt("Choice")

        if choice == "1":
            result = self.app.relock_file(temp_filename, original_hash)
            _show_result(result)
        else:
            _info(f"File left at: {temp_path}")
            _info("Remember to relock it when done.")

        _press_enter()

    def _handle_list(self):
        _clear()
        _banner()
        print(f"  {BOLD}Your Vault{RESET}\n")

        result = self.app.list_files()

        if not result["success"] or result["data"]["count"] == 0:
            _info("Your vault is empty.")
        else:
            files = result["data"]["files"]
            print(f"  {DIM}{'#':<5} {'Filename':<45} {'Type'}{RESET}")
            print(f"  {DIM}{'─'*60}{RESET}")
            for i, f in enumerate(files, 1):
                ext  = Path(f).stem.split(".")[-1].upper() if "." in Path(f).stem else "FILE"
                print(f"  {CYAN}{i:<5}{RESET} {f:<45} {DIM}{ext}{RESET}")
            print(f"\n  {DIM}{result['message']}{RESET}")

        _press_enter()

    def _handle_delete(self):
        _clear()
        _banner()
        print(f"  {BOLD}Delete a file{RESET}")
        _info("This is permanent. There is no recovery.")
        print()

        self._print_vault_files()

        enc_filename = _prompt("Filename to delete")

        if not enc_filename:
            _err("No filename entered. Cancelled.")
            _press_enter()
            return

        print(f"\n  {RED}WARNING: '{enc_filename}' will be permanently deleted.{RESET}")
        confirm = _prompt("Type the filename again to confirm")

        if confirm != enc_filename:
            _info("Filename mismatch. Cancelled.")
            _press_enter()
            return

        result = self.app.delete_file(enc_filename)
        _show_result(result)
        _press_enter()

    def _handle_audit_log(self):
        _clear()
        _banner()
        print(f"  {BOLD}Audit Log{RESET}\n")

        if self.app._db:
            try:
                logs = self.app._db.get_logs(user_id=self.app.session.user_id, limit=20)
                if not logs:
                    _info("No audit logs found.")
                else:
                    print(f"  {DIM}{'Timestamp':<22} {'Action':<10} {'Status':<12} {'File'}{RESET}")
                    print(f"  {DIM}{'─'*70}{RESET}")
                    for log in logs:
                        status_color = GREEN if log.get("success") else RED
                        print(
                            f"  {DIM}{log.get('timestamp',''):<22}{RESET}"
                            f" {CYAN}{log.get('action',''):<10}{RESET}"
                            f" {status_color}{log.get('status',''):<12}{RESET}"
                            f" {log.get('original_name','')}"
                        )
            except Exception as e:
                _err(f"Could not fetch logs: {e}")
        else:
            _info("Audit logging is not available (audit_db.py not connected).")

        _press_enter()

    # ══════════════════════════════════════════
    # Utility
    # ══════════════════════════════════════════
    def _print_vault_files(self):
        """Inline file list — shown before decrypt/open/delete prompts."""
        result = self.app.list_files()
        files  = result["data"].get("files", [])

        if files:
            print(f"  {DIM}Files in your vault:{RESET}")
            for f in files:
                print(f"    {DIM}•{RESET} {f}")
            print()
        else:
            _info("Your vault is empty.")

    def _handle_delete_account(self):
        _clear()
        _banner()
        print(f"  {RED}{BOLD}Delete Account{RESET}")
        _info("This will export ALL your vault files, then permanently wipe your account.")
        _info("Your audit logs will be kept. This cannot be undone.")
        print()

        # ── Show what will be exported ──
        self._print_vault_files()

        # ── Pick export directory ──
        _info("Enter a FOLDER path where your files will be exported to.")
        _info("Example: C:\\Users\\Jerush\\Desktop\\my_exports")
        export_dir = _prompt("Export directory (full folder path)")
        if not export_dir:
            _err("Export directory cannot be empty. Cancelled.")
            _press_enter()
            return
            _press_enter()
            return

        # ── Password confirmation ──
        print(f"\n  {YELLOW}Enter your password to confirm deletion:{RESET}")
        password = _password_prompt("Password")

        # ── Final warning ──
        print(f"\n  {RED}FINAL WARNING: Account and vault will be permanently deleted.{RESET}")
        confirm = _prompt("Type DELETE to confirm")

        if confirm != "DELETE":
            _info("Cancelled — account is safe.")
            _press_enter()
            return

        # ── Call core ──
        print(f"\n  {DIM}Exporting files and deleting account...{RESET}")
        result = self.app.delete_account(password, export_dir)
        _show_result(result)

        if result["success"]:
            data            = result.get("data", {})
            exported_files  = data.get("exported_files", [])
            failed_files    = data.get("failed_files", [])
            export_dir_out  = data.get("export_dir", export_dir)

            if exported_files:
                print(f"\n  {DIM}Exported files:{RESET}")
                for f in exported_files:
                    print(f"    {GREEN}✓{RESET}  {f}")
            if failed_files:
                print(f"\n  {DIM}Failed to export:{RESET}")
                for f in failed_files:
                    print(f"    {RED}✗{RESET}  {f}")
            _info(f"Files saved to: {export_dir_out}")

        _press_enter()
        _clear()
        _banner()

    def _exit(self):
        if self.app.session.active:
            self.app.logout()
        print(f"\n  {DIM}Goodbye.{RESET}\n")
        sys.exit(0)


# ══════════════════════════════════════════════
# Entry
# ══════════════════════════════════════════════
if __name__ == "__main__":
    try:
        CipherNestCLI().run()
    except KeyboardInterrupt:
        print(f"\n\n  {DIM}Interrupted. Goodbye.{RESET}\n")
        sys.exit(0)
