from app.models import ParsedEmail
from app.detection.detector import PhishingDetector

detector = PhishingDetector()

phishing_email = ParsedEmail(
    message_id="p1", api_key_id="k", sender="alerts@totally-not-paypal.ru",
    recipient="v@x.com", subject="Your PayPal account has been suspended",
    reply_to="support@some-other-domain.ru",
    html_body="<p>Dear customer, verify your account and enter your password immediately. Your account will be closed. <a href='http://bit.ly/pp-verify'>Click here</a></p>",
)

legit_reset_email = ParsedEmail(
    message_id="l1", api_key_id="k", sender="accounts@acmeshop.com",
    recipient="v@x.com", subject="Reset your password",
    reply_to="accounts@acmeshop.com",
    html_body="<p>We received a request to reset your password. Click below to reset your password. If you did not request this, ignore this email.</p><a href='https://acmeshop.com/reset?token=123'>Reset password</a>",
)

result1 = detector.scan(phishing_email)
print("PHISHING EMAIL RESULT:")
print(result1)
print()

result2 = detector.scan(legit_reset_email)
print("LEGIT RESET EMAIL RESULT:")
print(result2)

borderline_email = ParsedEmail(
    message_id="b1", api_key_id="k", sender="promotions@dealz-xyz.top",
    recipient="v@x.com", subject="Limited time offer",
    html_body="<p>Act now! This offer won't last. <a href='https://dealz-xyz.top/deals'>See deals</a></p>",
)

result3 = detector.scan(borderline_email)
print("BORDERLINE EMAIL RESULT:")
print(result3)