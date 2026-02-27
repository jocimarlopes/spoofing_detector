"""
Spoofing Detector — Configuration
All variables are loaded from the .env file.
"""

import os
from dataclasses import dataclass, field
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


def _bool(key: str, default: bool) -> bool:
    val = os.getenv(key, str(default)).lower()
    return val in ("true", "1", "yes")


@dataclass
class SMTPConfig:
    """SMTP relay server settings."""
    host: str = field(default_factory=lambda: os.getenv("SMTP_HOST", "smtp.hostinger.com"))
    port: int = field(default_factory=lambda: int(os.getenv("SMTP_PORT", "465")))
    use_ssl: bool = field(default_factory=lambda: _bool("SMTP_USE_SSL", True))
    use_tls: bool = field(default_factory=lambda: _bool("SMTP_USE_TLS", False))
    username: str = field(default_factory=lambda: os.getenv("SMTP_USERNAME", ""))
    password: str = field(default_factory=lambda: os.getenv("SMTP_PASSWORD", ""))
    timeout: int = field(default_factory=lambda: int(os.getenv("SMTP_TIMEOUT", "10")))


@dataclass
class SpoofConfig:
    """Spoofed email settings."""

    # Forged sender — what the recipient will see in the "From" field
    from_address: str = field(default_factory=lambda: os.getenv("SPOOF_FROM_ADDRESS", ""))
    display_name: str = field(default_factory=lambda: os.getenv("SPOOF_DISPLAY_NAME", ""))

    # Real envelope sender (SMTP MAIL FROM) — different from the visible From header
    envelope_from: Optional[str] = field(default_factory=lambda: os.getenv("SPOOF_ENVELOPE_FROM") or None)

    to_address: str = field(default_factory=lambda: os.getenv("SPOOF_TO_ADDRESS", ""))
    reply_to: Optional[str] = field(default_factory=lambda: os.getenv("SPOOF_REPLY_TO") or None)
    subject: str = "[POC] Spoofing Test"

    body_text: str = field(default_factory=lambda: (
        "This is a proof-of-concept email demonstrating an email spoofing vulnerability.\n\n"
        "This message appears to be sent by {from_address}, but it was actually sent "
        "from an external server without valid SPF/DKIM/DMARC authentication.\n\n"
        "Please inspect the full email headers to confirm the actual origin.\n\n"
        "-- Authorized security test --"
    ).format(from_address=os.getenv("SPOOF_FROM_ADDRESS", "")))

    body_html: Optional[str] = field(default_factory=lambda: (
        "<html><body>"
        "<p>This is a <strong>proof-of-concept email demonstrating an email spoofing vulnerability</strong>.</p>"
        "<p>This message appears to be sent by <code>{from_address}</code>, but it was actually sent "
        "from an external server <strong>without valid SPF/DKIM/DMARC authentication</strong>.</p>"
        "<p>Please inspect the full email headers to confirm the actual origin.</p>"
        "<hr><small>Authorized security test</small>"
        "</body></html>"
    ).format(from_address=os.getenv("SPOOF_FROM_ADDRESS", "")))


@dataclass
class LocalRelayConfig:
    """Local SMTP relay server settings (local_relay.py)."""
    host: str = field(default_factory=lambda: os.getenv("LOCAL_RELAY_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("LOCAL_RELAY_PORT", "2525")))
