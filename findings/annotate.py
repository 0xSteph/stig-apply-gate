"""Write register results back into a STIG Viewer checklist.

The checklist keeps its STATUS. Only the finding-details and comments fields of
matched rules change, and existing text in them is kept above a dated marker.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from xml.etree import ElementTree as ET

from findings.models import normalize_rule_id
from findings.parsers import cklb_host, cklb_rule_id, local_name, read_cklb

_PROLOG = re.compile(r"^﻿?\s*(?:(?:<\?.*?\?>|<!--.*?-->|<!DOCTYPE[^>]*>)\s*)*", re.DOTALL)
_ENCODING = re.compile(r"""(encoding\s*=\s*)(["'])([^"']*)\2""")


def annotate_checklist(ledger: dict, checklist: Path, out: Path) -> dict:
    """Copy checklist to out with register notes on every rule the ledger matches."""
    if _same_path(checklist, out):
        raise ValueError(f"Refusing to write {out}. That is the input checklist. Choose a different --out.")
    suffix = checklist.suffix.lower()
    index = _FindingIndex(ledger)
    if suffix == ".cklb":
        return _annotate_cklb(index, checklist, out)
    if suffix == ".ckl":
        return _annotate_ckl(index, checklist, out)
    raise ValueError(f"{checklist}: annotate reads .ckl or .cklb checklists only.")


def register_block(finding: dict, decision: dict | None, as_of: str) -> str:
    lines = [marker(as_of)]
    due = finding.get("due") or "none"
    lines.append(f"Clock: {finding.get('clock')}. Due: {due}. CAT {finding.get('cat')}.")
    if finding.get("exception_id"):
        lines.append(f"Exception: {finding['exception_id']}.")
    if decision:
        reason = (decision.get("reason") or "").strip()
        lines.append(f"Apply gate: {decision.get('action')}." + (f" {reason}" if reason else ""))
    return "\n".join(lines)


def marker(as_of: str) -> str:
    return f"--- findings register {as_of} ---"


def append_block(existing: str | None, block: str) -> str:
    text = (existing or "").rstrip()
    if not text:
        return block
    if text.endswith(block):
        # Already annotated with this exact block. Do not stack a copy.
        return text
    return f"{text}\n\n{block}"


class _FindingIndex:
    def __init__(self, ledger: dict) -> None:
        self.as_of = str(ledger.get("generated_for") or "")
        self.by_key: dict[tuple[str, str, str], dict] = {}
        for finding in ledger.get("findings") or []:
            host = str(finding.get("host") or "").lower()
            for kind, value in _identifiers(finding.get("rule_ver"), finding.get("vuln_num"), finding.get("rule_id")):
                self.by_key.setdefault((host, kind, value), finding)
        decisions = (ledger.get("apply_gate") or {}).get("decisions") or []
        self.decisions = {(str(item.get("host") or "").lower(), item.get("control")): item for item in decisions}

    def match(self, hosts: set[str], rule_ver, vuln_num, rule_id) -> tuple[dict, dict | None] | None:
        for kind, value in _identifiers(rule_ver, vuln_num, rule_id):
            for host in hosts:
                finding = self.by_key.get((host, kind, value))
                if finding is not None:
                    decision = self.decisions.get((str(finding["host"]).lower(), finding.get("control")))
                    return finding, decision
        return None


def _identifiers(rule_ver, vuln_num, rule_id) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if rule_ver and str(rule_ver).strip():
        pairs.append(("rule_ver", str(rule_ver).strip()))
    if vuln_num and str(vuln_num).strip():
        pairs.append(("vuln_num", str(vuln_num).strip()))
    if rule_id and str(rule_id).strip():
        pairs.append(("rule_id", normalize_rule_id(str(rule_id))))
    return pairs


def _annotate_cklb(index: _FindingIndex, checklist: Path, out: Path) -> dict:
    raw = checklist.read_text(encoding="utf-8-sig")
    document = read_cklb(checklist)
    target = document.get("target_data") or {}
    hosts = {
        str(value).strip().lower()
        for value in (target.get("host_name"), target.get("fqdn"), cklb_host(document))
        if value and str(value).strip()
    }
    if not hosts:
        raise ValueError(f"{checklist} checklist has no host name in target_data.host_name or target_data.fqdn")
    total = 0
    matched = 0
    for stig in document["stigs"]:
        if not isinstance(stig, dict):
            continue
        for rule in stig.get("rules") or []:
            if not isinstance(rule, dict):
                continue
            total += 1
            hit = index.match(hosts, rule.get("rule_version"), rule.get("group_id") or rule.get("group_id_src"), cklb_rule_id(rule))
            if hit is None:
                continue
            block = register_block(hit[0], hit[1], index.as_of)
            rule["finding_details"] = append_block(rule.get("finding_details"), block)
            rule["comments"] = append_block(rule.get("comments"), block)
            matched += 1
    indent = 2 if "\n" in raw.strip() else None
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(document, indent=indent, ensure_ascii=False) + ("\n" if indent else ""), encoding="utf-8")
    return {"checklist": str(checklist), "out": str(out), "hosts": sorted(hosts), "rules": total, "matched": matched}


def _annotate_ckl(index: _FindingIndex, checklist: Path, out: Path) -> dict:
    data = checklist.read_bytes()
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True, insert_pis=True))
    try:
        root = ET.fromstring(data, parser=parser)
    except ET.ParseError as exc:
        raise ValueError(f"{checklist} is not valid XML: {exc}") from exc
    if local_name(root.tag).upper() != "CHECKLIST":
        raise ValueError(f"{checklist} is not a STIG Viewer checklist. The root element is {local_name(root.tag)}.")
    hosts: set[str] = set()
    for element in root.iter():
        if not isinstance(element.tag, str):
            continue
        if local_name(element.tag) in {"HOST_NAME", "HOST_FQDN"} and (element.text or "").strip():
            hosts.add(element.text.strip().lower())
    if not hosts:
        raise ValueError(f"{checklist} checklist has no host name")
    total = 0
    matched = 0
    for vuln in root.iter():
        if not isinstance(vuln.tag, str) or local_name(vuln.tag) != "VULN":
            continue
        total += 1
        attrs: dict[str, str] = {}
        for child in list(vuln):
            if not isinstance(child.tag, str) or local_name(child.tag) != "STIG_DATA":
                continue
            key = value = ""
            for field in list(child):
                if not isinstance(field.tag, str):
                    continue
                if local_name(field.tag) == "VULN_ATTRIBUTE":
                    key = (field.text or "").strip()
                elif local_name(field.tag) == "ATTRIBUTE_DATA":
                    value = (field.text or "").strip()
            if key and key not in attrs:
                attrs[key] = value
        hit = index.match(hosts, attrs.get("Rule_Ver"), attrs.get("Vuln_Num"), attrs.get("Rule_ID"))
        if hit is None:
            continue
        block = register_block(hit[0], hit[1], index.as_of)
        for name in ("FINDING_DETAILS", "COMMENTS"):
            element = _child(vuln, name)
            element.text = append_block(element.text, block)
        matched += 1

    # ElementTree drops what sits before the root (the declaration and the STIG Viewer
    # comment), so that text is carried over as written. The copy is always UTF-8,
    # and it keeps the input's line endings.
    text = data.decode("utf-8-sig", errors="replace")
    prolog = _PROLOG.match(text).group(0)
    prolog = _ENCODING.sub(_utf8_declaration, prolog)
    body = ET.tostring(root, encoding="unicode")
    newline = "\r\n" if "\r\n" in text else "\n"
    result = prolog.replace("\r\n", "\n") + body
    if text.endswith(("\n", "\r")):
        result += "\n"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(result.replace("\n", newline), encoding="utf-8", newline="")
    return {"checklist": str(checklist), "out": str(out), "hosts": sorted(hosts), "rules": total, "matched": matched}


def _utf8_declaration(match: re.Match) -> str:
    if match.group(3).strip().lower().replace("_", "-") in {"utf-8", "utf8"}:
        return match.group(0)
    quote = match.group(2)
    return f"{match.group(1)}{quote}UTF-8{quote}"


def _child(vuln: ET.Element, name: str) -> ET.Element:
    """The named child of a VULN. Created after STATUS, in STIG Viewer order, when missing."""
    children = list(vuln)
    for child in children:
        if isinstance(child.tag, str) and local_name(child.tag) == name:
            return child
    namespace = vuln.tag[: -len(local_name(vuln.tag))]
    element = ET.Element(namespace + name)
    order = ["STATUS", "FINDING_DETAILS", "COMMENTS"]
    position = len(children)
    for offset, child in enumerate(children):
        if isinstance(child.tag, str) and local_name(child.tag) in order[: order.index(name)]:
            position = offset + 1
    element.tail = children[position - 1].tail if children and position > 0 else None
    vuln.insert(position, element)
    return element


def _same_path(left: Path, right: Path) -> bool:
    try:
        if right.exists() and os.path.samefile(left, right):
            return True
    except OSError:
        pass
    return os.path.normcase(str(left.resolve())) == os.path.normcase(str(right.resolve()))
