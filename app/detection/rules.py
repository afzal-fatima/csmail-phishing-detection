import re

URGENCY_PHRASES = [
    "verify your account", "account suspended", "confirm your identity",
    "your account will be closed", "unusual activity detected",
    "immediate action required", "click here to verify", "act now",
    "your account has been locked", "security alert", "unauthorized login",
    "final notice", "update your payment", "reactivate your account",
]

CREDENTIAL_HARVEST_PHRASES = [
    "confirm your password", "enter your password", "verify your password",
    "confirm your ssn", "social security number", "enter your pin",
    "confirm your credit card", "update your billing information",
]

FINANCIAL_LURE_PHRASES = [
    "you have won", "claim your prize", "you are eligible for a refund",
    "tax refund", "wire transfer", "unclaimed funds", "lottery winner",
    "free gift card",
]

GENERIC_SALUTATIONS = [
    "dear customer", "dear user", "dear valued customer", "dear member",
]

IMPERSONATED_BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com"],
    "netflix": ["netflix.com"],
    "docusign": ["docusign.com", "docusign.net"],
}

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
]

SUSPICIOUS_TLDS = [
    ".zip", ".top", ".xyz", ".club", ".tk", ".click",
]

TRANSACTIONAL_MARKERS = [
    "order confirmation", "your receipt", "invoice #", "tracking number",
    "shipping confirmation", "this is an automated message",
    "if you did not request this", "reset your password", "one-time code",
    "verification code", "your order has shipped",
]

def _find_phrases(text, phrases):
    text_lower = text.lower()
    return [p for p in phrases if p in text_lower]

def check_urgency_language(email):
    hits = _find_phrases(email.full_text, URGENCY_PHRASES)
    if hits:
        return True, f"Urgency/pressure language found: {', '.join(hits[:3])}"
    return False, ""

def check_credential_harvest(email):
    hits = _find_phrases(email.full_text, CREDENTIAL_HARVEST_PHRASES)
    if hits:
        return True, f"Requests credentials/PII directly: {', '.join(hits[:3])}"
    return False, ""


def check_financial_lure(email):
    hits = _find_phrases(email.full_text, FINANCIAL_LURE_PHRASES)
    if hits:
        return True, f"Financial lure/prize language: {', '.join(hits[:3])}"
    return False, ""

def check_brand_impersonation(email):
    text_lower = email.full_text.lower()
    evidences = []

    for brand, legit_domains in IMPERSONATED_BRANDS.items():
        if brand in text_lower:
            sender_domain = email.sender_domain.lower()
            link_domains = [d.lower() for d in email.link_domains]
            all_domains = [sender_domain] + link_domains

            matches_brand = any(
                domain == legit or domain.endswith("." + legit)
                for domain in all_domains
                for legit in legit_domains
            )

            if not matches_brand:
                evidences.append(
                    f"Mentions '{brand}' but sender/link domains ({sender_domain}) don't belong to {brand}"
                )

    if evidences:
        return True, "; ".join(evidences)
    return False, ""


def check_url_shorteners(email):
    hits = [d for d in email.link_domains if d.lower() in URL_SHORTENERS]
    if hits:
        return True, f"Uses URL shortener(s): {', '.join(set(hits))}"
    return False, ""


def check_suspicious_tlds(email):
    hits = [d for d in email.link_domains if any(d.lower().endswith(t) for t in SUSPICIOUS_TLDS)]
    if hits:
        return True, f"Link(s) use suspicious domain ending: {', '.join(set(hits))}"
    return False, ""

def check_reply_to_mismatch(email):
    if email.reply_to and email.sender_domain:
        reply_domain = email.reply_to.split("@")[-1].lower()
        if reply_domain != email.sender_domain.lower():
            return True, f"Reply-To domain ('{reply_domain}') differs from sending domain ('{email.sender_domain}')"
    return False, ""


def check_attachment_risk(email):
    risky_ext = (".exe", ".scr", ".js", ".vbs", ".bat", ".hta")
    hits = [a for a in email.attachments if a.lower().endswith(risky_ext)]
    if hits:
        return True, f"Risky attachment type(s): {', '.join(hits)}"
    return False, ""

def check_generic_salutation_plus_link(email):
    hits = _find_phrases(email.full_text, GENERIC_SALUTATIONS)
    if hits and email.links:
        return True, f"Generic salutation ('{hits[0]}') combined with an embedded link"
    return False, ""

RULES = [
    ("urgency_language", 10, check_urgency_language),
    ("credential_harvest", 50, check_credential_harvest),
    ("financial_lure", 30, check_financial_lure),
    ("brand_impersonation", 50, check_brand_impersonation),
    ("url_shortener", 20, check_url_shorteners),
    ("suspicious_tld", 10, check_suspicious_tlds),
    ("reply_to_mismatch", 30, check_reply_to_mismatch),
    ("attachment_risk", 40, check_attachment_risk),
    ("generic_salutation_link", 10, check_generic_salutation_plus_link),
]

