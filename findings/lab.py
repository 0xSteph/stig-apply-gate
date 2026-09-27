"""Integration Lab is a synthetic unclassified lab used to show the weekly loop.

The scan files it writes are the same shapes SCC, STIG Viewer, and ACAS emit.
The findings are invented. The rule identifiers that carry a vuln number are
public STIG identifiers, with one-line titles written for this lab.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from xml.etree import ElementTree as ET

from findings.vsphere import ESXI_CHECKS

NS = "http://checklists.nist.gov/xccdf/1.2"

RHEL_RULES = {
    "RHEL-08-010370": {
        "vuln_num": "V-230264",
        "rule_id": "SV-230264r880711_rule",
        "severity": "high",
        "cci": ["CCI-001749"],
        "nist": ["CM-5"],
        "title": "Repository packages must be GPG-checked before they are installed.",
    },
    "RHEL-08-010371": {
        "vuln_num": "V-230265",
        "rule_id": "SV-230265r877463_rule",
        "severity": "high",
        "cci": ["CCI-001749"],
        "nist": ["CM-5"],
        "title": "Local packages must be GPG-checked before they are installed.",
    },
    "RHEL-08-010550": {
        "vuln_num": "V-230296",
        "rule_id": "SV-230296r858711_rule",
        "severity": "medium",
        "cci": ["CCI-000770"],
        "nist": ["IA-2"],
        "title": "Direct SSH logons as root must be disabled.",
    },
    "RHEL-08-020230": {
        "vuln_num": "V-230369",
        "rule_id": "SV-230369r858785_rule",
        "severity": "medium",
        "cci": ["CCI-000205"],
        "nist": ["IA-5"],
        "title": "Passwords must be at least 15 characters.",
    },
    "RHEL-08-030180": {
        "vuln_num": "V-230411",
        "rule_id": "SV-230411r744000_rule",
        "severity": "medium",
        "cci": ["CCI-000169"],
        "nist": ["AU-12"],
        "title": "The audit package must be installed.",
    },
}

WINDOWS_RULES = {
    "WN22-00-000380": {
        "vuln_num": "V-254275",
        "rule_id": "SV-254275r958478_rule",
        "severity": "medium",
        "cci": ["CCI-000381"],
        "nist": [],
        "title": "The SMBv1 feature must not be installed.",
    },
    "WN22-AC-000070": {
        "vuln_num": "",
        "rule_id": "",
        "severity": "medium",
        "cci": [],
        "nist": ["IA-5"],
        "title": "Minimum password length must be 14 characters.",
    },
    "WN22-DC-000060": {
        "vuln_num": "",
        "rule_id": "",
        "severity": "medium",
        "cci": [],
        "nist": [],
        "title": "Domain controller clock skew must stay within five minutes.",
    },
}

# host, date, rule, result, comment
RHEL_RESULTS = [
    ("rhel-repo01.lab.local", "2026-07-15", "RHEL-08-010370", "fail", "gpgcheck=0 on lab.repo."),
    ("rhel-repo01.lab.local", "2026-08-20", "RHEL-08-010370", "fail", ""),
    ("rhel-repo01.lab.local", "2026-09-20", "RHEL-08-010370", "fail", "Key is in the build notes. It was never imported on this host."),
    ("rhel-repo01.lab.local", "2026-07-15", "RHEL-08-010371", "pass", ""),
    ("rhel-repo01.lab.local", "2026-08-20", "RHEL-08-010371", "fail", "Kickstart rewrite dropped localpkg_gpgcheck."),
    ("rhel-repo01.lab.local", "2026-09-20", "RHEL-08-010371", "fail", ""),
    ("rhel-repo01.lab.local", "2026-07-15", "RHEL-08-010550", "fail", ""),
    ("rhel-repo01.lab.local", "2026-08-20", "RHEL-08-010550", "fail", ""),
    ("rhel-repo01.lab.local", "2026-09-20", "RHEL-08-010550", "pass", "Closed during the repo host window. sshd restarted from the console."),
    ("rhel-repo01.lab.local", "2026-07-15", "RHEL-08-020230", "fail", ""),
    ("rhel-repo01.lab.local", "2026-08-20", "RHEL-08-020230", "fail", ""),
    ("rhel-repo01.lab.local", "2026-09-20", "RHEL-08-020230", "fail", "minlen is still 8."),
    ("rhel-repo01.lab.local", "2026-07-15", "RHEL-08-030180", "pass", ""),
    ("rhel-repo01.lab.local", "2026-08-20", "RHEL-08-030180", "pass", ""),
    ("rhel-repo01.lab.local", "2026-09-20", "RHEL-08-030180", "pass", ""),
    ("rhel-mission01.lab.local", "2026-07-15", "RHEL-08-010370", "pass", ""),
    ("rhel-mission01.lab.local", "2026-08-20", "RHEL-08-010370", "pass", ""),
    ("rhel-mission01.lab.local", "2026-09-20", "RHEL-08-010370", "pass", ""),
    ("rhel-mission01.lab.local", "2026-07-15", "RHEL-08-010371", "pass", ""),
    ("rhel-mission01.lab.local", "2026-08-20", "RHEL-08-010371", "fail", ""),
    ("rhel-mission01.lab.local", "2026-09-20", "RHEL-08-010371", "fail", "Same kickstart as the repo host."),
    ("rhel-mission01.lab.local", "2026-07-15", "RHEL-08-010550", "pass", ""),
    ("rhel-mission01.lab.local", "2026-08-20", "RHEL-08-010550", "fail", "Root SSH was turned on during a late debug and left there."),
    ("rhel-mission01.lab.local", "2026-09-20", "RHEL-08-010550", "fail", "Console is the iDRAC on the bench. Restart sshd only with someone standing there."),
    ("rhel-mission01.lab.local", "2026-07-15", "RHEL-08-020230", "pass", ""),
    ("rhel-mission01.lab.local", "2026-08-20", "RHEL-08-020230", "pass", ""),
    ("rhel-mission01.lab.local", "2026-09-20", "RHEL-08-020230", "pass", ""),
    ("rhel-mission01.lab.local", "2026-07-15", "RHEL-08-030180", "pass", ""),
    ("rhel-mission01.lab.local", "2026-08-20", "RHEL-08-030180", "pass", ""),
    ("rhel-mission01.lab.local", "2026-09-20", "RHEL-08-030180", "fail", "audit RPM is gone after the September update."),
]

WINDOWS_RESULTS = [
    ("ad01.lab.local", "2026-07-15", "WN22-DC-000060", "pass", ""),
    ("ad01.lab.local", "2026-08-20", "WN22-DC-000060", "fail", "w32tm shows the peer is esxi01."),
    ("ad01.lab.local", "2026-09-20", "WN22-DC-000060", "fail", "Do not tighten Kerberos tolerance until ESXi stops using this DC for NTP."),
    ("ad01.lab.local", "2026-07-15", "WN22-AC-000070", "pass", "Domain policy is 14."),
    ("ad01.lab.local", "2026-08-20", "WN22-AC-000070", "pass", ""),
    ("ad01.lab.local", "2026-09-20", "WN22-AC-000070", "pass", ""),
    ("ad01.lab.local", "2026-07-15", "WN22-00-000380", "pass", ""),
    ("ad01.lab.local", "2026-08-20", "WN22-00-000380", "pass", ""),
    ("ad01.lab.local", "2026-09-20", "WN22-00-000380", "pass", ""),
    ("wsus01.lab.local", "2026-07-15", "WN22-00-000380", "fail", "FS-SMB1 is installed."),
    ("wsus01.lab.local", "2026-08-20", "WN22-00-000380", "fail", "Still required by the payload dropbox."),
    ("wsus01.lab.local", "2026-09-20", "WN22-00-000380", "fail", "Dropbox migration finished 1 Sep. Feature is still installed."),
    ("wsus01.lab.local", "2026-07-15", "WN22-AC-000070", "fail", "Member server OU is not linked to the password GPO."),
    ("wsus01.lab.local", "2026-08-20", "WN22-AC-000070", "fail", ""),
    ("wsus01.lab.local", "2026-09-20", "WN22-AC-000070", "fail", "Effective length is 8. Fix the GPO link, not the local policy."),
]

ESXI_RESULTS = [
    ("esxi01.lab.local", "2026-07-15", "ESXI-80-000008", "pass", "Lockdown is Normal."),
    ("esxi01.lab.local", "2026-08-20", "ESXI-80-000008", "pass", ""),
    ("esxi01.lab.local", "2026-07-15", "ESXI-80-000193", "fail", "SSH left running after the build."),
    ("esxi01.lab.local", "2026-08-20", "ESXI-80-000193", "fail", "Break-glass for the integration campaign. See EX-014."),
    ("esxi01.lab.local", "2026-07-15", "ESXI-80-000124", "pass", "Two external sources."),
    ("esxi01.lab.local", "2026-08-20", "ESXI-80-000124", "fail", "Only peer is ad01, and ad01 takes time from this host."),
    ("esxi01.lab.local", "2026-07-15", "ESXI-80-000114", "fail", "Syslog.global.logHost is empty."),
    ("esxi01.lab.local", "2026-08-20", "ESXI-80-000114", "fail", "No collector on the lab network yet."),
]

ACAS_ROWS = [
    ("2026-08-20", "rhel-mission01.lab.local", "187315", "CVE-2023-48795", "5.9", "Medium", "SSH prefix truncation can weaken the handshake."),
    ("2026-09-05", "rhel-mission01.lab.local", "187315", "CVE-2023-48795", "5.9", "Medium", "SSH prefix truncation can weaken the handshake."),
    ("2026-09-05", "rhel-mission01.lab.local", "201194", "CVE-2024-6387", "8.1", "High", "OpenSSH signal-handler race during authentication."),
    ("2026-09-20", "rhel-mission01.lab.local", "187315", "CVE-2023-48795", "5.9", "Medium", "SSH prefix truncation can weaken the handshake."),
    ("2026-09-20", "rhel-mission01.lab.local", "201194", "CVE-2024-6387", "8.1", "High", "OpenSSH signal-handler race during authentication."),
]


def write_lab_scans(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for host, day in _pairs(RHEL_RESULTS):
        rows = [row for row in RHEL_RESULTS if row[0] == host and row[1] == day]
        _write_xccdf(root / f"{host.split('.')[0]}_{day}.xml", host, day, "Red Hat Enterprise Linux 8 STIG", RHEL_RULES, rows)
    for host, day in _pairs(WINDOWS_RESULTS):
        rows = [row for row in WINDOWS_RESULTS if row[0] == host and row[1] == day]
        _write_ckl(
            root / f"{host.split('.')[0]}_{day}.ckl",
            host,
            day,
            "Microsoft Windows Server 2022 Security Technical Implementation Guide",
            WINDOWS_RULES,
            rows,
        )
    for host, day in _pairs(ESXI_RESULTS):
        rows = [row for row in ESXI_RESULTS if row[0] == host and row[1] == day]
        _write_ckl(
            root / f"{host.split('.')[0]}_{day}.ckl",
            host,
            day,
            "VMware vSphere 8.0 ESXi STIG",
            ESXI_CHECKS,
            rows,
        )
    by_day: dict[str, list] = {}
    for row in ACAS_ROWS:
        by_day.setdefault(row[0], []).append(row)
    for day, rows in by_day.items():
        _write_csv(root / f"acas_{day}.csv", rows)
    snapshot = {
        "host": "esxi01.lab.local",
        "observed_at": "2026-09-20",
        "lockdown_mode": "lockdownNormal",
        "ssh_running": True,
        "ntp_running": True,
        "ntp_servers": ["ad01.lab.local"],
        "ntp_circular_with": ["ad01.lab.local"],
        "syslog_log_host": "",
    }
    (root / "esxi01_2026-09-20.json").write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")


def _pairs(rows: list[tuple]) -> list[tuple[str, str]]:
    seen = []
    for host, day, *_rest in rows:
        if (host, day) not in seen:
            seen.append((host, day))
    return seen


def _write_xccdf(path: Path, host: str, day: str, benchmark_title: str, rules: dict, rows: list[tuple]) -> None:
    ET.register_namespace("", NS)
    benchmark = ET.Element(f"{{{NS}}}Benchmark", {"id": "xccdf_lab_benchmark"})
    title = ET.SubElement(benchmark, f"{{{NS}}}title")
    title.text = benchmark_title
    for _host, _day, rule, _result, _comment in rows:
        meta = rules[rule]
        group = ET.SubElement(benchmark, f"{{{NS}}}Group", {"id": f"xccdf_lab_group_{meta['vuln_num'] or rule}"})
        rule_el = ET.SubElement(
            group,
            f"{{{NS}}}Rule",
            {"id": f"xccdf_mil.disa.stig_rule_{meta['rule_id']}", "severity": meta["severity"]},
        )
        version = ET.SubElement(rule_el, f"{{{NS}}}version")
        version.text = rule
        rule_title = ET.SubElement(rule_el, f"{{{NS}}}title")
        rule_title.text = meta["title"]
        for cci in meta.get("cci") or []:
            ident = ET.SubElement(rule_el, f"{{{NS}}}ident", {"system": "http://cyber.mil/cci"})
            ident.text = cci
        if meta.get("vuln_num"):
            ident = ET.SubElement(rule_el, f"{{{NS}}}ident", {"system": "http://cyber.mil/legacy"})
            ident.text = meta["vuln_num"]
        for nist in meta.get("nist") or []:
            ident = ET.SubElement(rule_el, f"{{{NS}}}ident", {"system": "http://cyber.mil/nist"})
            ident.text = nist
    test = ET.SubElement(
        benchmark,
        f"{{{NS}}}TestResult",
        {"id": f"xccdf_lab_testresult_{day}", "start-time": f"{day}T02:10:00"},
    )
    target = ET.SubElement(test, f"{{{NS}}}target")
    target.text = host
    for _host, _day, rule, result, comment in rows:
        meta = rules[rule]
        rule_result = ET.SubElement(
            test,
            f"{{{NS}}}rule-result",
            {"idref": f"xccdf_mil.disa.stig_rule_{meta['rule_id']}", "severity": meta["severity"]},
        )
        result_el = ET.SubElement(rule_result, f"{{{NS}}}result")
        result_el.text = result
        if comment:
            comment_el = ET.SubElement(rule_result, f"{{{NS}}}message")
            comment_el.text = comment
    ET.indent(benchmark, space="  ")
    ET.ElementTree(benchmark).write(path, encoding="utf-8", xml_declaration=True)


def _write_ckl(path: Path, host: str, day: str, stig_title: str, rules: dict, rows: list[tuple]) -> None:
    checklist = ET.Element("CHECKLIST")
    asset = ET.SubElement(checklist, "ASSET")
    host_name = ET.SubElement(asset, "HOST_NAME")
    host_name.text = host.split(".")[0]
    fqdn = ET.SubElement(asset, "HOST_FQDN")
    fqdn.text = host
    stigs = ET.SubElement(checklist, "STIGS")
    istig = ET.SubElement(stigs, "iSTIG")
    info = ET.SubElement(istig, "STIG_INFO")
    _si(info, "title", stig_title)
    status_map = {"fail": "Open", "pass": "NotAFinding", "notapplicable": "Not_Applicable"}
    for _host, _day, rule, result, comment in rows:
        meta = rules[rule]
        vuln = ET.SubElement(istig, "VULN")
        _stig_data(vuln, "Vuln_Num", meta.get("vuln_num") or "")
        _stig_data(vuln, "Severity", meta["severity"])
        _stig_data(vuln, "Rule_ID", meta.get("rule_id") or "")
        _stig_data(vuln, "Rule_Ver", rule)
        _stig_data(vuln, "Rule_Title", meta["title"])
        for cci in meta.get("cci") or []:
            _stig_data(vuln, "CCI_REF", cci)
        status = ET.SubElement(vuln, "STATUS")
        status.text = status_map[result]
        details = ET.SubElement(vuln, "FINDING_DETAILS")
        details.text = comment
        comments = ET.SubElement(vuln, "COMMENTS")
        comments.text = comment
        override = ET.SubElement(vuln, "SEVERITY_OVERRIDE")
        override.text = ""
        justification = ET.SubElement(vuln, "SEVERITY_JUSTIFICATION")
        justification.text = ""
    ET.indent(checklist, space="  ")
    ET.ElementTree(checklist).write(path, encoding="utf-8", xml_declaration=True)


def _write_csv(path: Path, rows: list[tuple]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Plugin ID", "CVE", "CVSS", "Risk", "Host", "Name", "Synopsis"])
        for _day, host, plugin, cve, cvss, risk, synopsis in rows:
            writer.writerow([plugin, cve, cvss, risk, host, synopsis, synopsis])


def _si(parent: ET.Element, name: str, value: str) -> None:
    data = ET.SubElement(parent, "SI_DATA")
    sid_name = ET.SubElement(data, "SID_NAME")
    sid_name.text = name
    sid_data = ET.SubElement(data, "SID_DATA")
    sid_data.text = value


def _stig_data(parent: ET.Element, key: str, value: str) -> None:
    data = ET.SubElement(parent, "STIG_DATA")
    attr = ET.SubElement(data, "VULN_ATTRIBUTE")
    attr.text = key
    body = ET.SubElement(data, "ATTRIBUTE_DATA")
    body.text = value
