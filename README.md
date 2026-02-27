# Spoofing Detector

Email spoofing POC tool. Demonstrates vulnerabilities when SPF, DKIM, and DMARC are missing or misconfigured.

> **Warning:** Authorized security testing only. Unauthorized use is illegal.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configure

Edit `.env` with:
- SMTP relay credentials
- Spoofed sender address
- Target recipient
- Envelope sender

## Usage

### Interactive Menu (Recommended)

```bash
python main.py
```

Menu options:
- **Domain Analysis** — Check SPF/DKIM/DMARC records
- **Send Spoofed Email** — Choose delivery mode (relay/direct/local)
- **Local Relay Server** — Start/stop background relay
- **View Configuration** — Show current .env settings

### Command Line (Direct)

```bash
# Check domain records
python check_records.py example.com

# Send spoofed email
python spoof.py                # via relay
python spoof.py --direct       # direct to MX (port 25)
python spoof.py --local        # via local relay

# Start local relay
python local_relay.py
```

## What to Look For

Inspect email headers for:
- **From:** forged address (appears legitimate)
- **Return-Path:** real origin (reveals the spoofing)
- **Received-SPF:** softfail/fail (shows unauthorized sender)
- **DMARC-Filter:** none policy (no action taken)

## Dependencies

- `dnspython` — DNS lookups
- `aiosmtpd` — local SMTP server
- `python-dotenv` — config from `.env`
