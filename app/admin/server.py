from flask import Flask, render_template_string
import json
from app.models import ParsedEmail
from app.detection.detector import PhishingDetector
from app.dkim_dmarc.validator import DkimDmarcValidator

app = Flask(__name__)

detector = PhishingDetector()


def load_emails(filepath):
    with open(filepath, "r") as f:
        raw_list = json.load(f)
    return [ParsedEmail(**item) for item in raw_list]

PAGE_TEMPLATE = """
<html>
<head>
  <title>CSMail Admin - Phishing Detection</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2rem; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; font-size: 14px; }
    th { background: #eee; }
    .phishing { background: #ffdddd; }
    .suspicious { background: #fff3cd; }
    .clean { background: #ddffdd; }
  </style>
</head>
<body>
  <h1>CSMail Admin - Scanned Emails</h1>
  <table>
    <tr><th>Sender</th><th>Subject</th><th>Score</th><th>Classification</th><th>Reasons</th></tr>
    {% for r in results %}
    <tr class="{{ r.classification }}">
      <td>{{ r.sender }}</td>
      <td>{{ r.subject }}</td>
      <td>{{ r.score }}</td>
      <td>{{ r.classification }}</td>
      <td>
        {% for rule_name, weight, evidence in r.hits %}
          &bull; {{ evidence }}<br/>
        {% endfor %}
      </td>
    </tr>
    {% endfor %}
  </table>
    <h2>DKIM / DMARC Validation</h2>
  <table>
    <tr><th>Domain</th><th>DKIM</th><th>DMARC</th><th>Overall</th></tr>
    {% for r in dkim_dmarc_results %}
    <tr>
      <td>{{ r.domain }}</td>
      <td>{{ 'PASS' if r.dkim.passed else 'FAIL: ' + r.dkim.explanation }}</td>
      <td>{{ 'PASS' if r.dmarc.passed else 'FAIL: ' + r.dmarc.explanation }}</td>
      <td>{{ 'PASS' if r.overall_pass else 'FAIL' }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""



@app.route("/")
def dashboard():
    phishing_emails = load_emails("data/sample_phishing_emails.json")
    legit_emails = load_emails("data/sample_legit_emails.json")
    all_emails = phishing_emails + legit_emails

    results = []
    for email in all_emails:
        result = detector.scan(email)
        results.append({
            "sender": email.sender,
            "subject": email.subject,
            "score": result["score"],
            "classification": result["classification"],
            "hits": result["hits"],
        })
    results.sort(key=lambda r: r["score"], reverse=True)
    validator = DkimDmarcValidator()
    dkim_dmarc_results = [
      validator.validate_domain("google.com", "20230601"),
    ]
    return render_template_string(PAGE_TEMPLATE, results=results, dkim_dmarc_results=dkim_dmarc_results)


if __name__ == "__main__":
    app.run(debug=True, port=5001)