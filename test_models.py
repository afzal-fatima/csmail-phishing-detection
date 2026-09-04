from datetime import date, timedelta
from app.warmup.warmup_manager import WarmupManager

manager = WarmupManager()
start = date.today() - timedelta(days=10)
manager.add_domain("marketing.acmeshop.com", started_on=start)

day = start
while day <= date.today():
    manager.record_send_result("marketing.acmeshop.com", sent=30, bounced=1, on_day=day)
    result = manager.evaluate_and_advance("marketing.acmeshop.com", on_day=day)
    print(day, result)
    day += timedelta(days=1)

print()
print("Final status:", manager.get_status("marketing.acmeshop.com"))

print()
print("=" * 40)
print("Testing a domain with a high bounce rate:")

manager.add_domain("risky.acmeshop.com", started_on=start)
day = start
while day <= date.today():
    manager.record_send_result("risky.acmeshop.com", sent=100, bounced=20, on_day=day)
    result = manager.evaluate_and_advance("risky.acmeshop.com", on_day=day)
    print(day, result)
    day += timedelta(days=1)