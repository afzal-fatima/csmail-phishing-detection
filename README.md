# CSMail Phishing & Abuse Detection Module

A prototype built for the internship task assigned by Qasim (Aug 22, 2026): phishing detection, domain warm-up logic, and DKIM/DMARC validation for the CSMail transactional email platform.

## Setup

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

## Run the demo
python3 run_demo.py

This prints:
1. A scan of 5 sample phishing emails and 5 sample legitimate emails, showing which were flagged and why (5/5 phishing correctly flagged, 0/5 legitimate emails falsely flagged).
2. A simulation of three domains in warm-up: a brand-new domain, a domain with 10 days of healthy sending history (which advances through several stages), and a domain with a high bounce rate (which is correctly held back).
3. Live DKIM/DMARC validation against a real domain over actual DNS, showing pass/fail and explanations for any misconfiguration.

## Run the admin panel
python3 -m app.admin.server

Then open `http://localhost:5001` in a browser. Shows all scanned emails (sorted by risk score, color-coded, with flag reasons), and DKIM/DMARC validation results, in one dashboard.

## Project structure
app/
models.py - ParsedEmail data model (parses sender, links, domains from raw email data)
detection/
rules.py - 9 phishing detection rules (keyword and pattern matching)
detector.py - Scoring engine: combines rules into clean/suspicious/phishing classification
warmup/
warmup_manager.py - Domain warm-up state machine (staged volume ramp, bounce-rate gating)
dkim_dmarc/
validator.py - DNS-based DKIM/DMARC validation with human-readable fix explanations
admin/
server.py - Flask admin dashboard
data/
sample_phishing_emails.json - 5 test phishing emails
sample_legit_emails.json - 5 test legitimate transactional emails
run_demo.py - Runs all three components end-to-end


## How the phishing detector works

Each outgoing email is checked against 9 independent rules (urgency language, credential harvesting, financial lures, brand impersonation, URL shorteners, suspicious TLDs, reply-to mismatches, risky attachments, and generic salutations paired with links). Each rule has a weight based on how strong a signal it is — for example, a request for a password (weight 50) counts far more than generic urgency language (weight 10), since the former is nearly impossible for a legitimate email to trigger by accident.

Scores are summed and mapped to clean / suspicious / phishing. Emails containing transactional markers (order confirmations, tracking numbers, "if you did not request this") have their score reduced, unless the evidence against them is already overwhelming — this prevents false positives on real receipts and password resets while still catching phishing emails that try to disguise themselves with similar boilerplate language.

## How domain warm-up works

New domains start at a low daily sending cap (50/day) and advance through 8 stages toward an unlimited cap, based on both time elapsed and sending health. A domain with a bounce rate above 5% is held at its current stage regardless of how many days have passed, until its sending health improves.

## How DKIM/DMARC validation works

Looks up a domain's DKIM record (at `<selector>._domainkey.<domain>`) and DMARC record (at `_dmarc.<domain>`) over live DNS, checks they're correctly formatted and enforcing (e.g. DMARC's `p=none` is treated as not enforcing), and returns a specific explanation of what's wrong and what to fix if validation fails.

## Known limitations / next steps

- This is a prototype using sample data, not wired into CSMail's actual live email-sending path.
- Rule weights are tuned against 10 sample emails; would benefit from a larger, real-world test set before production use.
- The admin panel uses in-memory data on each page load rather than a persistent database.
- Domain warm-up advancement (`evaluate_and_advance`) is designed to run daily via a scheduled job; currently invoked manually in the demo.