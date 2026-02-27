"""
Spoofing Detector — Local SMTP Open Relay

Listens on localhost:2525, accepts any MAIL FROM without authentication,
and delivers directly to the recipient's MX server via IPv4 port 25.

Usage:
    python local_relay.py
"""

import asyncio
import smtplib
import socket
import dns.resolver
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage
from config import LocalRelayConfig

_cfg = LocalRelayConfig()
HOST = _cfg.host
PORT = _cfg.port


def resolve_mx_ipv4(domain: str) -> tuple:
    """Returns the hostname and IPv4 address of the highest-priority MX for a domain."""
    answers = dns.resolver.resolve(domain, "MX")
    records = sorted(answers, key=lambda r: r.preference)
    mx_host = str(records[0].exchange).rstrip(".")
    ipv4 = socket.getaddrinfo(mx_host, 25, socket.AF_INET)[0][4][0]
    return mx_host, ipv4


class ForwardingHandler(AsyncMessage):
    """Accepts email locally and forwards it to the recipient's MX server."""

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        mail_from = envelope.mail_from
        rcpt_to = envelope.rcpt_tos[0] if envelope.rcpt_tos else ""
        to_domain = rcpt_to.split("@")[-1] if "@" in rcpt_to else ""

        print(f"\n[>] Message received by local relay")
        print(f"    MAIL FROM : {mail_from}")
        print(f"    RCPT TO   : {rcpt_to}")

        if not to_domain:
            print("[!] No recipient — discarded")
            return "550 No recipients"

        try:
            mx_host, ipv4 = resolve_mx_ipv4(to_domain)
            print(f"[*] Forwarding to MX: {mx_host} ({ipv4}):25")

            conn = smtplib.SMTP(ipv4, 25, timeout=15)
            conn.ehlo()
            conn.sendmail(
                from_addr=mail_from,
                to_addrs=envelope.rcpt_tos,
                msg=envelope.content
            )
            conn.quit()
            print(f"[+] Successfully delivered to {rcpt_to}")
            return "250 Message accepted"

        except Exception as e:
            print(f"[!] Delivery failed: {e}")
            return f"451 Temporary failure: {e}"


def main():
    handler = ForwardingHandler()
    controller = Controller(handler, hostname=HOST, port=PORT)
    controller.start()

    print(f"[*] Local SMTP relay running on {HOST}:{PORT}")
    print(f"[*] Accepts any MAIL FROM — delivers directly to the recipient's MX")
    print(f"[*] Press Ctrl+C to stop\n")

    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        controller.stop()


if __name__ == "__main__":
    main()
