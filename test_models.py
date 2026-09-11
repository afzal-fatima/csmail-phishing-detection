from app.dkim_dmarc.validator import DkimDmarcValidator

validator = DkimDmarcValidator()

result = validator.check_dkim("google.com", "20230601")
print(result)

result = validator.check_dmarc("google.com")
print(result)

result = validator.validate_domain("google.com", "20230601")
print(result)