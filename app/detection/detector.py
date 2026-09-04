from app.detection.rules import RULES, TRANSACTIONAL_MARKERS

FLAG_THRESHOLD = 55
SUSPICIOUS_THRESHOLD = 20


class PhishingDetector:
    def scan(self, email):
        hits = []
        score = 0

        for rule_name, weight, rule_function in RULES:
            triggered, evidence = rule_function(email)
            if triggered:
                hits.append((rule_name, weight, evidence))
                score += weight
        
        text = email.full_text.lower()
        has_transactional_markers = any(marker in text for marker in TRANSACTIONAL_MARKERS)
        if has_transactional_markers and score < FLAG_THRESHOLD:
            score = int(score * 0.4)

        if score >= FLAG_THRESHOLD:
            classification = "phishing"
        elif score >= SUSPICIOUS_THRESHOLD:
            classification = "suspicious"
        else:
            classification = "clean"

        is_flagged = classification == "phishing"

        return {
            "score": score,
            "classification": classification,
            "is_flagged": is_flagged,
            "hits": hits,
        }