from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date


FAIL_RESULTS = {"fail", "error"}
PASS_RESULTS = {"pass", "notapplicable"}


@dataclass
class Observation:
    host: str
    observed_at: date
    source: str
    source_file: str
    benchmark: str = ""
    rule_ver: str | None = None
    vuln_num: str | None = None
    rule_id: str | None = None
    plugin_id: str | None = None
    cve: str | None = None
    title: str = ""
    severity: str | None = None
    severity_override: str | None = None
    severity_verified: bool = True
    cci: list[str] = field(default_factory=list)
    nist: list[str] = field(default_factory=list)
    result: str = "fail"
    comments: str = ""
    detail: str = ""
    cvss: float | None = None
    platform: str = ""

    def identifiers(self) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        if self.rule_ver:
            pairs.append(("rule_ver", self.rule_ver.strip()))
        if self.vuln_num:
            pairs.append(("vuln_num", self.vuln_num.strip()))
        if self.rule_id:
            pairs.append(("rule_id", normalize_rule_id(self.rule_id)))
        if self.cve:
            pairs.append(("cve", self.cve.strip().upper()))
        if self.plugin_id:
            pairs.append(("plugin", str(self.plugin_id).strip()))
        return pairs


def normalize_rule_id(value: str) -> str:
    text = value.strip()
    marker = "rule_"
    if marker in text:
        text = text.split(marker, 1)[1]
    return text


def slug_for(host: str, control: str) -> str:
    short = host.split(".")[0].lower()
    safe = []
    for char in control:
        safe.append(char if char.isalnum() else "-")
    collapsed = "".join(safe).strip("-")
    while "--" in collapsed:
        collapsed = collapsed.replace("--", "-")
    return f"{short}--{collapsed}"
