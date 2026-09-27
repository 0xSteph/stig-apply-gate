from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path


@dataclass(frozen=True)
class Policy:
    sla_days: dict[str, int]
    due_soon_days: int = 21
    regression_restarts_clock: bool = True
    exception_grace_days: int = 0
    cvss_cat_i_min: float = 7.0
    cvss_cat_ii_min: float = 4.0

    def cat_for_cvss(self, score: float) -> str:
        if score >= self.cvss_cat_i_min:
            return "I"
        if score >= self.cvss_cat_ii_min:
            return "II"
        return "III"


DEFAULT_POLICY = Policy(sla_days={"I": 30, "II": 90, "III": 365})


def load_policy(path: str | Path) -> Policy:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    sla = {str(key): int(value) for key, value in data["sla_days"].items()}
    return Policy(
        sla_days=sla,
        due_soon_days=int(data.get("due_soon_days", 21)),
        regression_restarts_clock=bool(data.get("regression_restarts_clock", True)),
        exception_grace_days=int(data.get("exception_grace_days", 0)),
        cvss_cat_i_min=float(data.get("cvss_cat_i_min", 7.0)),
        cvss_cat_ii_min=float(data.get("cvss_cat_ii_min", 4.0)),
    )


def parse_day(value: str | date) -> date:
    if isinstance(value, date):
        return value
    return date.fromisoformat(value[:10])
