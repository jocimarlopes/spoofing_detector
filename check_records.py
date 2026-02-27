"""
Spoofing Detector — DNS Authentication Record Checker
Checks for missing or misconfigured SPF, DKIM, and DMARC records on a domain.
"""

import dns.resolver
import sys
from typing import Optional


def check_spf(domain: str) -> dict:
    """Checks the SPF record and identifies weak policies."""
    result = {"found": False, "record": None, "issues": []}
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                result["found"] = True
                result["record"] = txt

                if "~all" in txt:
                    result["issues"].append(
                        "Weak policy 'softfail' (~all): unauthorized emails are accepted with a warning, not rejected."
                    )
                elif "?all" in txt:
                    result["issues"].append(
                        "Weak policy 'neutral' (?all): any server can send mail, no real validation enforced."
                    )
                elif "+all" in txt:
                    result["issues"].append(
                        "CRITICAL: Policy '+all' allows ANY server to send email on behalf of this domain."
                    )
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        result["issues"].append("No SPF record found: domain is vulnerable to envelope spoofing.")
    except Exception as e:
        result["issues"].append(f"Error querying SPF: {e}")
    return result


def check_dmarc(domain: str) -> dict:
    """Checks the DMARC record and identifies permissive policies."""
    result = {"found": False, "record": None, "issues": []}
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                result["found"] = True
                result["record"] = txt

                if "p=none" in txt:
                    result["issues"].append(
                        "DMARC policy 'none': emails that fail authentication are still delivered (monitoring only)."
                    )
                elif "p=quarantine" in txt:
                    result["issues"].append(
                        "DMARC policy 'quarantine': suspicious emails may go to spam, but are not rejected."
                    )
                break
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        result["issues"].append("No DMARC record found: no rejection policy for unauthenticated emails.")
    except Exception as e:
        result["issues"].append(f"Error querying DMARC: {e}")
    return result


def check_dkim(domain: str, selectors: Optional[list] = None) -> dict:
    """Searches common DKIM selectors to detect missing cryptographic signatures."""
    if selectors is None:
        selectors = ["default", "google", "mail", "smtp", "dkim", "k1", "selector1", "selector2"]

    result = {"found": False, "selector": None, "record": None, "issues": []}

    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            for rdata in answers:
                txt = rdata.to_text().strip('"')
                if "v=DKIM1" in txt or "p=" in txt:
                    result["found"] = True
                    result["selector"] = selector
                    result["record"] = txt[:80] + "..." if len(txt) > 80 else txt
                    break
            if result["found"]:
                break
        except Exception:
            continue

    if not result["found"]:
        result["issues"].append(
            f"No DKIM record found (selectors tested: {', '.join(selectors)}). "
            "Emails from this domain have no cryptographic signature."
        )

    return result


def check_mx(domain: str) -> list:
    """Returns the MX servers for a domain, sorted by priority."""
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return sorted(
            [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
            key=lambda x: x[0]
        )
    except Exception:
        return []


def run_check(domain: str):
    print(f"\n{'='*60}")
    print(f"  Email authentication analysis for: {domain}")
    print(f"{'='*60}\n")

    mx = check_mx(domain)
    if mx:
        print("[MX] Mail servers:")
        for pref, host in mx:
            print(f"     {pref} {host}")
    else:
        print("[MX] No MX records found.")
    print()

    spf = check_spf(domain)
    status = "OK" if (spf["found"] and not spf["issues"]) else ("WARNING" if spf["found"] else "VULNERABLE")
    print(f"[SPF] Status: {status}")
    if spf["record"]:
        print(f"      Record: {spf['record']}")
    for issue in spf["issues"]:
        print(f"      ! {issue}")
    print()

    dkim = check_dkim(domain)
    status = "OK" if dkim["found"] else "VULNERABLE"
    print(f"[DKIM] Status: {status}")
    if dkim["found"]:
        print(f"       Selector: {dkim['selector']}")
        print(f"       Record  : {dkim['record']}")
    for issue in dkim["issues"]:
        print(f"       ! {issue}")
    print()

    dmarc = check_dmarc(domain)
    status = "OK" if (dmarc["found"] and not dmarc["issues"]) else ("WARNING" if dmarc["found"] else "VULNERABLE")
    print(f"[DMARC] Status: {status}")
    if dmarc["record"]:
        print(f"        Record: {dmarc['record']}")
    for issue in dmarc["issues"]:
        print(f"        ! {issue}")
    print()

    vulnerable = not spf["found"] or not dkim["found"] or not dmarc["found"]
    weak_policy = bool(spf["issues"]) or bool(dmarc["issues"])

    print(f"{'='*60}")
    if vulnerable:
        print("  RESULT: Domain is VULNERABLE to email spoofing.")
    elif weak_policy:
        print("  RESULT: Domain has WEAK email authentication (permissive policy).")
    else:
        print("  RESULT: Email authentication is properly configured.")
    print(f"{'='*60}\n")

    return {"spf": spf, "dkim": dkim, "dmarc": dmarc, "mx": mx}


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else input("Target domain: ").strip()
    run_check(domain)
