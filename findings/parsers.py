from __future__ import annotations

import csv
import re
from datetime import date
from pathlib import Path
from xml.etree import ElementTree as ET

from findings.models import Observation

_DATE_IN_NAME = re.compile(r"(20\d{2}-\d{2}-\d{2})")

_RESULT_MAP = {
    "fail": "fail",
    "failed": "fail",
    "open": "fail",
    "pass": "pass",
    "passed": "pass",
    "notafinding": "pass",
    "not_a_finding": "pass",
    "not a finding": "pass",
    "notapplicable": "notapplicable",
    "not_applicable": "notapplicable",
    "not applicable": "notapplicable",
    "notchecked": "notchecked",
    "not_reviewed": "notchecked",
    "not reviewed": "notchecked",
    "error": "error",
    "unknown": "notchecked",
    "informational": "notchecked",
    "fixed": "pass",
    "notselected": "notapplicable",
}

_SEVERITY_MAP = {
    "critical": "high",
    "high": "high",
    "cat i": "high",
    "cati": "high",
    "i": "high",
    "medium": "medium",
    "moderate": "medium",
    "cat ii": "medium",
    "catii": "medium",
    "ii": "medium",
    "low": "low",
    "cat iii": "low",
    "catiii": "low",
    "iii": "low",
}


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def date_from_filename(path: Path) -> date | None:
    match = _DATE_IN_NAME.search(path.name)
    if not match:
        return None
    return date.fromisoformat(match.group(1))


def normalize_result(value: str | None, *, source: str = "") -> str:
    if not value or not value.strip():
        where = f" in {source}" if source else ""
        raise ValueError(f"A result{where} was blank. Expected Open, NotAFinding, Not_Applicable, Not_Reviewed, pass, or fail.")
    key = value.strip().lower()
    if key not in _RESULT_MAP:
        where = f" in {source}" if source else ""
        raise ValueError(
            f"Result {value!r}{where} was not recognized. "
            "Expected Open, NotAFinding, Not_Applicable, Not_Reviewed, pass, or fail."
        )
    return _RESULT_MAP[key]


def normalize_severity(value: str | None) -> str | None:
    if not value or not value.strip():
        return None
    return _SEVERITY_MAP.get(value.strip().lower())


def parse_scan(path: Path, observed_on: date | None = None) -> list[Observation]:
    suffix = path.suffix.lower()
    if suffix in {".ckl", ".xml"}:
        # CKL is XML too. Prefer the checklist root when present.
        try:
            root = ET.parse(path).getroot()
        except ET.ParseError as exc:
            raise ValueError(f"{path} is not valid XML: {exc}") from exc
        if local_name(root.tag).upper() == "CHECKLIST" or suffix == ".ckl":
            return parse_ckl(path, observed_on=observed_on)
        return parse_xccdf(path, observed_on=observed_on)
    if suffix == ".csv":
        return parse_acas(path, observed_on=observed_on)
    if suffix == ".json":
        return parse_vsphere_export(path, observed_on=observed_on)
    raise ValueError(f"Unsupported scan file: {path}")


def parse_xccdf(path: Path, observed_on: date | None = None) -> list[Observation]:
    root = ET.parse(path).getroot()
    rules: dict[str, dict] = {}
    benchmark = ""
    for element in root.iter():
        name = local_name(element.tag)
        if name == "Benchmark":
            for child in list(element):
                if local_name(child.tag) == "title" and child.text:
                    benchmark = child.text.strip()
                    break
        if name != "Rule":
            continue
        rule_id = element.attrib.get("id", "")
        version = ""
        title = ""
        cci: list[str] = []
        vulns: list[str] = []
        nist: list[str] = []
        for child in list(element):
            child_name = local_name(child.tag)
            text = (child.text or "").strip()
            if child_name == "version":
                version = text
            elif child_name == "title":
                title = text
            elif child_name == "ident" and text:
                system = child.attrib.get("system", "").lower()
                if text.startswith("CCI-") or "cci" in system:
                    cci.append(text)
                elif text.startswith("V-") or "legacy" in system:
                    vulns.append(text)
                else:
                    nist.append(text)
        rules[rule_id] = {
            "rule_ver": version or None,
            "title": title,
            "severity": normalize_severity(element.attrib.get("severity")),
            "cci": cci,
            "vuln_num": vulns[0] if vulns else None,
            "nist": nist,
            "rule_id": rule_id,
        }

    observations: list[Observation] = []
    for element in root.iter():
        if local_name(element.tag) != "TestResult":
            continue
        target = ""
        start = element.attrib.get("start-time", "")
        scanned = _day(start) or observed_on or date_from_filename(path)
        if scanned is None:
            raise ValueError(f"{path} has a TestResult without a start-time or a date in the filename")
        for child in list(element):
            if local_name(child.tag) == "target" and child.text:
                target = child.text.strip()
        if not target:
            raise ValueError(f"{path} TestResult is missing <target>")
        for child in list(element):
            if local_name(child.tag) != "rule-result":
                continue
            idref = child.attrib.get("idref", "")
            result = "notchecked"
            comments = ""
            for grandchild in list(child):
                if local_name(grandchild.tag) == "result":
                    result = normalize_result(grandchild.text, source=path.name)
                elif local_name(grandchild.tag) == "message" and (grandchild.text or "").strip():
                    comments = grandchild.text.strip()
            meta = rules.get(idref, {})
            observations.append(
                Observation(
                    host=target,
                    observed_at=scanned,
                    source="xccdf",
                    source_file=str(path),
                    benchmark=benchmark,
                    rule_ver=meta.get("rule_ver"),
                    vuln_num=meta.get("vuln_num"),
                    rule_id=meta.get("rule_id") or idref,
                    title=meta.get("title") or idref,
                    severity=meta.get("severity") or normalize_severity(child.attrib.get("severity")),
                    cci=list(meta.get("cci") or []),
                    nist=list(meta.get("nist") or []),
                    result=result,
                    comments=comments,
                    platform="rhel",
                )
            )
    if not observations:
        raise ValueError(
            f"{path} parsed as XML but contained no XCCDF rule results. "
            "This usually means the file is the benchmark only, not a scan result."
        )
    return observations


def parse_ckl(path: Path, observed_on: date | None = None) -> list[Observation]:
    root = ET.parse(path).getroot()
    host = ""
    benchmark = ""
    for element in root.iter():
        name = local_name(element.tag)
        if name in {"HOST_FQDN", "HOST_NAME"} and (element.text or "").strip() and not host:
            host = element.text.strip()
        if name == "HOST_FQDN" and (element.text or "").strip():
            host = element.text.strip()
        if name == "SID_NAME" and (element.text or "").strip() == "title":
            sibling = None
            parent = _parent_map(root).get(element)
            if parent is not None:
                children = list(parent)
                for index, child in enumerate(children):
                    if child is element and index + 1 < len(children):
                        sibling = children[index + 1]
                        break
            if sibling is not None and local_name(sibling.tag) == "SID_DATA":
                benchmark = (sibling.text or "").strip()
    if not host:
        raise ValueError(f"{path} checklist has no host name")
    scanned = observed_on or date_from_filename(path)
    if scanned is None:
        raise ValueError(f"{path} needs a YYYY-MM-DD in the filename or an observed date")

    observations: list[Observation] = []
    for vuln in root.iter():
        if local_name(vuln.tag) != "VULN":
            continue
        attrs: dict[str, list[str]] = {}
        status = "Not_Reviewed"
        comments = ""
        details = ""
        override = ""
        justification = ""
        for child in list(vuln):
            name = local_name(child.tag)
            if name == "STIG_DATA":
                key = ""
                value = ""
                for field in list(child):
                    if local_name(field.tag) == "VULN_ATTRIBUTE":
                        key = (field.text or "").strip()
                    elif local_name(field.tag) == "ATTRIBUTE_DATA":
                        value = (field.text or "").strip()
                if key:
                    attrs.setdefault(key, []).append(value)
            elif name == "STATUS":
                status = (child.text or "").strip()
            elif name == "COMMENTS":
                comments = (child.text or "").strip()
            elif name == "FINDING_DETAILS":
                details = (child.text or "").strip()
            elif name == "SEVERITY_OVERRIDE":
                override = (child.text or "").strip()
            elif name == "SEVERITY_JUSTIFICATION":
                justification = (child.text or "").strip()
        observations.append(
            Observation(
                host=host,
                observed_at=scanned,
                source="ckl",
                source_file=str(path),
                benchmark=benchmark,
                rule_ver=_first(attrs, "Rule_Ver"),
                vuln_num=_first(attrs, "Vuln_Num"),
                rule_id=_first(attrs, "Rule_ID"),
                title=_first(attrs, "Rule_Title") or _first(attrs, "Rule_Ver") or "",
                severity=normalize_severity(_first(attrs, "Severity")),
                severity_override=normalize_severity(override),
                cci=attrs.get("CCI_REF", []),
                result=normalize_result(status, source=path.name),
                comments=comments,
                detail=" ".join(part for part in (details, justification) if part),
                platform="stig",
            )
        )
    if not observations:
        raise ValueError(f"{path} parsed as a checklist but contained no VULN rows.")
    return observations


def parse_acas(path: Path, observed_on: date | None = None) -> list[Observation]:
    scanned = observed_on or date_from_filename(path)
    if scanned is None:
        raise ValueError(f"{path} needs a YYYY-MM-DD in the filename or an observed date")
    observations: list[Observation] = []
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError(f"{path} has no header row.")
        fields = {_norm_header(name): name for name in reader.fieldnames}
        if not any(name in fields for name in ("host", "hostname", "dns name")):
            found = ", ".join(reader.fieldnames)
            raise ValueError(
                f"{path} has no Host column. Headers found: {found}. "
                "Export the ACAS or Nessus CSV that includes Host. A .nessus XML file is not read."
            )
        skipped = 0
        for row in reader:
            host = _cell(row, fields, "host", "hostname", "dns name")
            if not host:
                skipped += 1
                continue
            risk = _cell(row, fields, "risk", "severity")
            if risk and risk.lower() in {"none", "info", "informational"}:
                continue
            cve = _cell(row, fields, "cve", "cves")
            if cve and "," in cve:
                cve = cve.split(",")[0].strip()
            cvss_text = _cell(row, fields, "cvss", "cvss v3.0 base score", "cvss v3 base score", "cvss3 base score")
            cvss = float(cvss_text) if cvss_text else None
            plugin = _cell(row, fields, "plugin id", "pluginid", "plugin")
            name = _cell(row, fields, "name", "plugin name", "title") or (cve or f"Plugin {plugin}")
            synopsis = _cell(row, fields, "synopsis", "description", "plugin output")
            observations.append(
                Observation(
                    host=host.strip(),
                    observed_at=scanned,
                    source="acas",
                    source_file=str(path),
                    benchmark="ACAS",
                    plugin_id=plugin or None,
                    cve=cve.upper() if cve else None,
                    title=name,
                    severity=normalize_severity(risk),
                    result="fail",
                    detail=synopsis,
                    cvss=cvss,
                    platform="vuln",
                )
            )
        if skipped:
            raise ValueError(
                f"{path}: {skipped} row(s) had no Host value. Fix the export and rerun. Nothing from this file was kept."
            )
        if not observations:
            raise ValueError(f"{path} had a Host column but no vulnerability rows.")
    return observations


def parse_vsphere_export(path: Path, observed_on: date | None = None) -> list[Observation]:
    import json

    from findings.vsphere import checks_from_snapshot, observations_from_checks

    snapshot = json.loads(path.read_text(encoding="utf-8"))
    if observed_on and "observed_at" not in snapshot:
        snapshot = {**snapshot, "observed_at": observed_on.isoformat()}
    checks = checks_from_snapshot(snapshot)
    return observations_from_checks(checks, source_file=str(path))


def load_scans(path: Path) -> tuple[list[Observation], list[str]]:
    """Read every export under path. Problems are returned instead of being skipped.

    A ledger is only safe to build when the problem list is empty. A file that
    failed to parse must not look like a host that passed.
    """
    import json

    problems: list[str] = []
    observations: list[Observation] = []
    files = [path] if path.is_file() else sorted(item for item in path.rglob("*") if item.is_file())
    skip_names = {"hosts.json", "exceptions.json", "backups.json", "services.json", "site.json", "milestones.json"}
    known = {".xml", ".ckl", ".csv", ".json"}
    for item in files:
        if item.name in skip_names:
            continue
        suffix = item.suffix.lower()
        if suffix not in known:
            problems.append(
                f"{item}: not a scan export. Readable files are .xml (XCCDF), .ckl (STIG Viewer), "
                ".csv (ACAS or Nessus), and .json (ESXi snapshot). Export .nessus results to CSV first."
            )
            continue
        try:
            found = parse_scan(item)
        except (ValueError, ET.ParseError, json.JSONDecodeError, csv.Error, OSError, KeyError) as exc:
            problems.append(f"{item}: {exc}")
            continue
        if not found:
            problems.append(f"{item}: parsed, but it contained no findings.")
            continue
        observations.extend(found)
    readable = [item for item in files if item.name not in skip_names]
    if not readable:
        problems.append(
            f"{path}: no scan exports were found. "
            "Expected .xml (XCCDF), .ckl (STIG Viewer), .csv (ACAS or Nessus), or .json (ESXi snapshot)."
        )
    return observations, problems


def _day(value: str) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _first(attrs: dict[str, list[str]], key: str) -> str | None:
    values = attrs.get(key) or []
    if not values or not values[0]:
        return None
    return values[0]


def _parent_map(root: ET.Element) -> dict[ET.Element, ET.Element]:
    return {child: parent for parent in root.iter() for child in list(parent)}


def _norm_header(name: str) -> str:
    return re.sub(r"\s+", " ", name.strip().lower())


def _cell(row: dict[str, str | None], fields: dict[str, str], *candidates: str) -> str:
    for candidate in candidates:
        original = fields.get(candidate)
        if original is None:
            continue
        value = row.get(original)
        if value:
            return value.strip()
    return ""
