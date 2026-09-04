import json
from app.models import ParsedEmail
from app.detection.detector import PhishingDetector


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