from datetime import date, timedelta

DEFAULT_WARMUP_PLAN = [
    {"stage": 1, "days": 3, "daily_cap": 50},
    {"stage": 2, "days": 3, "daily_cap": 150},
    {"stage": 3, "days": 4, "daily_cap": 500},
    {"stage": 4, "days": 4, "daily_cap": 1500},
    {"stage": 5, "days": 5, "daily_cap": 5000},
    {"stage": 6, "days": 5, "daily_cap": 15000},
    {"stage": 7, "days": 7, "daily_cap": 50000},
    {"stage": 8, "days": 0, "daily_cap": None},
]


class WarmupManager:
    def __init__(self, plan=None):
        self.plan = plan or DEFAULT_WARMUP_PLAN
        self.domains = {}

    def add_domain(self, domain, started_on=None):
        started_on = started_on or date.today()
        self.domains[domain] = {
            "started_on": started_on,
            "current_stage_index": 0,
            "stage_entered_on": started_on,
            "daily_sent": {},
        }

    def get_status(self, domain):
        record = self.domains[domain]
        stage_info = self.plan[record["current_stage_index"]]
        days_in_stage = (date.today() - record["stage_entered_on"]).days
        return {
            "domain": domain,
            "stage": stage_info["stage"],
            "daily_cap": stage_info["daily_cap"],
            "days_in_current_stage": days_in_stage,
        }

    def record_send_result(self, domain, sent=0, bounced=0, complaints=0, on_day=None):
        on_day = on_day or date.today()
        record = self.domains[domain]
        day_key = on_day.isoformat()
        if day_key not in record["daily_sent"]:
            record["daily_sent"][day_key] = 0
        record["daily_sent"][day_key] += sent

        if "bounced" not in record:
            record["bounced"] = 0
            record["complaints"] = 0
        record["bounced"] += bounced
        record["complaints"] += complaints

    def evaluate_and_advance(self, domain, on_day=None):
        on_day = on_day or date.today()
        record = self.domains[domain]
        stage_info = self.plan[record["current_stage_index"]]

        days_in_stage = (on_day - record["stage_entered_on"]).days
        is_last_stage = record["current_stage_index"] == len(self.plan) - 1

        total_sent = sum(record["daily_sent"].values())
        bounce_rate = record.get("bounced", 0) / total_sent if total_sent > 0 else 0

        if bounce_rate > 0.05:
            return {"action": "held", "reason": f"Bounce rate {bounce_rate:.1%} exceeds 5% threshold"}

        if not is_last_stage and days_in_stage >= stage_info["days"]:
            record["current_stage_index"] += 1
            record["stage_entered_on"] = on_day
            new_stage = self.plan[record["current_stage_index"]]
            return {"action": "advanced", "new_stage": new_stage["stage"]}

        return {"action": "unchanged", "days_in_stage": days_in_stage}