import json
from app.models import ParsedEmail
from app.detection.detector import PhishingDetector
from app.dkim_dmarc.validator import DkimDmarcValidator


def load_emails(filepath):
    with open(filepath, "r") as f:
        raw_list = json.load(f)
    return [ParsedEmail(**item) for item in raw_list]


detector = PhishingDetector()

print("=" * 60)
print("PHISHING EMAILS TEST SET")
print("=" * 60)

phishing_emails = load_emails("data/sample_phishing_emails.json")
correctly_flagged = 0

for email in phishing_emails:
    result = detector.scan(email)
    status = "FLAGGED" if result["is_flagged"] else "MISSED"
    if result["is_flagged"]:
        correctly_flagged += 1
    print(f"[{status}] {email.subject} (score={result['score']})")
    for rule_name, weight, evidence in result["hits"]:
        print(f"    - {rule_name}: {evidence}")

print()
print(f"Result: {correctly_flagged}/{len(phishing_emails)} phishing emails correctly flagged")
print()

print("=" * 60)
print("LEGITIMATE EMAILS TEST SET")
print("=" * 60)

legit_emails = load_emails("data/sample_legit_emails.json")
false_positives = 0

for email in legit_emails:
    result = detector.scan(email)
    status = "FALSE POSITIVE" if result["is_flagged"] else "OK"
    if result["is_flagged"]:
        false_positives += 1
    print(f"[{status}] {email.subject} (score={result['score']})")

print()
print(f"Result: {false_positives}/{len(legit_emails)} legitimate emails incorrectly flagged")

print()
print("=" * 60)
print("DOMAIN WARM-UP DEMO")
print("=" * 60)

from datetime import date, timedelta
from app.warmup.warmup_manager import WarmupManager

manager = WarmupManager()

# A brand new domain, just added today
manager.add_domain("newsender.acmeshop.com")
print("New domain status:", manager.get_status("newsender.acmeshop.com"))

# A domain with 10 days of healthy sending history
start = date.today() - timedelta(days=10)
manager.add_domain("marketing.acmeshop.com", started_on=start)
day = start
while day <= date.today():
    manager.record_send_result("marketing.acmeshop.com", sent=30, bounced=1, on_day=day)
    manager.evaluate_and_advance("marketing.acmeshop.com", on_day=day)
    day += timedelta(days=1)
print("Healthy domain (10 days) status:", manager.get_status("marketing.acmeshop.com"))

# A domain with a high bounce rate — should be held back
manager.add_domain("risky.acmeshop.com", started_on=start)
day = start
while day <= date.today():
    manager.record_send_result("risky.acmeshop.com", sent=100, bounced=20, on_day=day)
    result = manager.evaluate_and_advance("risky.acmeshop.com", on_day=day)
    day += timedelta(days=1)
print("Risky domain (10 days, high bounces) status:", manager.get_status("risky.acmeshop.com"))
print("Hold reason:", result["reason"])

print()
print("=" * 60)
print("DKIM / DMARC VALIDATION")
print("=" * 60)

validator = DkimDmarcValidator()
result = validator.validate_domain("google.com", "20230601")

print(f"Domain: {result['domain']}")
print(f"DKIM: {'PASS' if result['dkim']['passed'] else 'FAIL'} — {result['dkim']['explanation']}")
print(f"DMARC: {'PASS' if result['dmarc']['passed'] else 'FAIL'} — {result['dmarc']['explanation']}")
print(f"Overall: {'PASS' if result['overall_pass'] else 'FAIL'}")