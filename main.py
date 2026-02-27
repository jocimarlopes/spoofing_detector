"""
Spoofing Detector — Interactive CLI Menu
"""

import os
import sys
import subprocess
import threading
from config import SMTPConfig, SpoofConfig

# Global process handle for local relay
_local_relay_process = None


def clear_screen():
    """Clear terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def print_header():
    """Print application header."""
    print("\n" + "="*60)
    print("  SPOOFING DETECTOR — Interactive Menu")
    print("="*60 + "\n")


def print_menu():
    """Display main menu options."""
    print("Select an option:\n")
    print("  1) Domain Analysis       — Check SPF/DKIM/DMARC records")
    print("  2) Send Spoofed Email    — Launch email spoofing POC")
    print("  3) Local Relay Server    — Start/stop local SMTP relay")
    print("  4) View Configuration    — Show current .env settings")
    print("  5) Exit\n")


def domain_analysis():
    """Run domain analysis."""
    clear_screen()
    print_header()
    print("[*] Domain Analysis\n")
    domain = input("Enter target domain (e.g., example.com): ").strip()

    if not domain:
        print("[!] No domain specified.")
        input("\nPress Enter to continue...")
        return

    print()
    subprocess.run([sys.executable, "check_records.py", domain])
    input("\nPress Enter to return to menu...")


def send_spoofed_email():
    """Send spoofed email with mode selection."""
    clear_screen()
    print_header()
    print("[*] Send Spoofed Email\n")

    spoof_cfg = SpoofConfig()

    print(f"Current spoofing config from .env:")
    print(f"  From (visible)    : {spoof_cfg.display_name} <{spoof_cfg.from_address}>")
    print(f"  Envelope From     : {spoof_cfg.envelope_from or spoof_cfg.from_address}")
    print(f"  To                : {spoof_cfg.to_address}")
    print()

    print("Delivery mode:\n")
    print("  1) SMTP Relay (default)       — Uses credentials from .env")
    print("  2) Direct to MX (port 25)     — Bypass relay, direct to recipient MX")
    print("  3) Local Relay (localhost)    — Via local open relay on port 2525")
    print("  4) Cancel\n")

    choice = input("Choose delivery mode [1-4]: ").strip()

    if choice == "1":
        print("\n[*] Sending via SMTP relay...")
        subprocess.run([sys.executable, "spoof.py"])
    elif choice == "2":
        print("\n[*] Sending directly to MX...")
        subprocess.run([sys.executable, "spoof.py", "--direct"])
    elif choice == "3":
        print("\n[*] Sending via local relay...")
        subprocess.run([sys.executable, "spoof.py", "--local"])
    elif choice == "4":
        return
    else:
        print("[!] Invalid choice.")

    input("\nPress Enter to return to menu...")


def local_relay_manager():
    """Manage local relay server (start/stop)."""
    global _local_relay_process

    clear_screen()
    print_header()
    print("[*] Local Relay Server\n")

    if _local_relay_process and _local_relay_process.poll() is None:
        print("Status: RUNNING (PID: {})".format(_local_relay_process.pid))
        print("\nOptions:\n")
        print("  1) Stop the relay")
        print("  2) Back to menu\n")

        choice = input("Choose [1-2]: ").strip()

        if choice == "1":
            print("\n[*] Stopping relay...")
            _local_relay_process.terminate()
            try:
                _local_relay_process.wait(timeout=3)
                print("[+] Relay stopped.")
            except subprocess.TimeoutExpired:
                _local_relay_process.kill()
                print("[+] Relay killed.")
            _local_relay_process = None
            input("\nPress Enter to continue...")
    else:
        print("Status: NOT RUNNING\n")
        print("Options:\n")
        print("  1) Start the relay")
        print("  2) Back to menu\n")

        choice = input("Choose [1-2]: ").strip()

        if choice == "1":
            print("\n[*] Starting local relay (localhost:2525)...")
            try:
                _local_relay_process = subprocess.Popen(
                    [sys.executable, "local_relay.py"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                print("[+] Relay started in background.")
                print(f"[+] PID: {_local_relay_process.pid}")
                print("\nRelay is listening on 127.0.0.1:2525")
                print("You can now send emails via: python spoof.py --local")
            except Exception as e:
                print(f"[!] Failed to start relay: {e}")
            input("\nPress Enter to continue...")


def view_configuration():
    """Display current configuration from .env."""
    clear_screen()
    print_header()
    print("[*] Current Configuration\n")

    smtp_cfg = SMTPConfig()
    spoof_cfg = SpoofConfig()

    print("[SMTP Relay]")
    print(f"  Host     : {smtp_cfg.host}")
    print(f"  Port     : {smtp_cfg.port}")
    print(f"  SSL      : {smtp_cfg.use_ssl}")
    print(f"  TLS      : {smtp_cfg.use_tls}")
    print(f"  Username : {smtp_cfg.username}")
    print()

    print("[Spoofing Target]")
    print(f"  From (visible)  : {spoof_cfg.display_name} <{spoof_cfg.from_address}>")
    print(f"  Envelope From   : {spoof_cfg.envelope_from}")
    print(f"  To              : {spoof_cfg.to_address}")
    print(f"  Subject         : {spoof_cfg.subject}")
    print(f"  Reply-To        : {spoof_cfg.reply_to or '(none)'}")
    print()

    print("To modify, edit the .env file and restart this menu.\n")
    input("Press Enter to continue...")


def main():
    """Main menu loop."""
    while True:
        clear_screen()
        print_header()
        print_menu()

        choice = input("Enter choice [1-5]: ").strip()

        if choice == "1":
            domain_analysis()
        elif choice == "2":
            send_spoofed_email()
        elif choice == "3":
            local_relay_manager()
        elif choice == "4":
            view_configuration()
        elif choice == "5":
            if _local_relay_process and _local_relay_process.poll() is None:
                print("\n[*] Stopping background relay...")
                _local_relay_process.terminate()
            print("\n[+] Goodbye.\n")
            break
        else:
            print("[!] Invalid choice. Please select 1-5.")
            input("\nPress Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[*] Interrupted by user.")
        if _local_relay_process and _local_relay_process.poll() is None:
            _local_relay_process.terminate()
        sys.exit(0)
