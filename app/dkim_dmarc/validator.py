import re
import dns.resolver


class DkimDmarcValidator:
    def check_dkim(self, domain, selector):
        query_name = f"{selector}._domainkey.{domain}"

        try:
            answers = dns.resolver.resolve(query_name, "TXT", lifetime=5.0)
            records = [b"".join(r.strings).decode() for r in answers]
        except Exception:
            records = []

        if not records:
            return {
                "passed": False,
                "record_found": False,
                "explanation": f"No DKIM record found at '{query_name}'. Add a TXT record there containing your DKIM public key (v=DKIM1; k=rsa; p=<key>).",
            }

        raw = records[0]
        issues = []

        if "v=dkim1" not in raw.lower():
            issues.append("missing 'v=DKIM1' tag")

        p_match = re.search(r"p=([^;]*)", raw, re.IGNORECASE)
        if not p_match or not p_match.group(1).strip():
            issues.append("empty or missing 'p=' public key")

        passed = not issues
        if passed:
            explanation = "DKIM record is valid."
        else:
            explanation = f"DKIM record found but misconfigured: {', '.join(issues)}. Fix: republish the TXT record at '{query_name}' with a complete 'v=DKIM1; k=rsa; p=<key>' value."

        return {"passed": passed, "record_found": True, "raw_record": raw, "explanation": explanation}

    def check_dmarc(self, domain):
        query_name = f"_dmarc.{domain}"

        try:
            answers = dns.resolver.resolve(query_name, "TXT", lifetime=5.0)
            records = [b"".join(r.strings).decode() for r in answers]
        except Exception:
            records = []

        dmarc_records = [r for r in records if r.lower().strip().startswith("v=dmarc1")]

        if not dmarc_records:
            return {
                "passed": False,
                "record_found": False,
                "explanation": f"No DMARC record found at '{query_name}'. Add a TXT record like: 'v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@{domain}'.",
            }

        raw = dmarc_records[0]
        policy_match = re.search(r"p=([^;]+)", raw, re.IGNORECASE)
        policy = policy_match.group(1).strip().lower() if policy_match else None

        passed = policy in ("quarantine", "reject")

        if passed:
            explanation = f"DMARC is enforcing with policy '{policy}'."
        elif policy == "none":
            explanation = f"DMARC policy is 'p=none' — monitor-only, not enforcing. Fix: change to 'p=quarantine' or 'p=reject' at '{query_name}' once legitimate mail is confirmed to pass alignment."
        else:
            explanation = f"DMARC record found but missing or invalid policy tag. Fix: add 'p=quarantine' or 'p=reject' at '{query_name}'."

        return {"passed": passed, "record_found": True, "raw_record": raw, "explanation": explanation}


    def validate_domain(self, domain, dkim_selector):
        dkim_result = self.check_dkim(domain, dkim_selector)
        dmarc_result = self.check_dmarc(domain)
        return {
            "domain": domain,
            "dkim": dkim_result,
            "dmarc": dmarc_result,
            "overall_pass": dkim_result["passed"] and dmarc_result["passed"],
        }

    