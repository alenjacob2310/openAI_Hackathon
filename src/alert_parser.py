"""Alert log parser — extracts IoCs and attack classifications from raw JSON alerts."""

from __future__ import annotations

import json
import re
import ipaddress
from pathlib import PureWindowsPath
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ParsedAlert(BaseModel):
    """Structured output from the alert parser."""

    alert_id: str = "UNKNOWN"
    timestamp: str = ""
    severity: str = "Unknown"
    source: str = ""
    rule_name: str = ""
    attack_classification: str = "Unknown"
    mitre_techniques: list[str] = Field(default_factory=list)
    iocs: dict[str, list[str]] = Field(default_factory=dict)
    related_cves: list[str] = Field(default_factory=list)
    summary: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


# Keyword → playbook classification mapping
_CLASSIFICATION_RULES: list[tuple[str, list[str]]] = [
    (
        "Phishing",
        [
            "phish",
            "phishing",
            "credential harvest",
            "spear",
            "bec",
            "malicious email",
            "evil-secure-login",
            "t1566",
        ],
    ),
    (
        "Ransomware",
        [
            "ransomware",
            "encrypt",
            "encrypting",
            "encrypted",
            "ransom",
            "shadow copy",
            "vssadmin",
            "t1486",
            ".locked",
        ],
    ),
    (
        "Credential Stuffing",
        [
            "credential stuffing",
            "stuffing",
            "distributed login",
            "combo",
            "t1110.004",
        ],
    ),
    (
        "DDoS",
        [
            "ddos",
            "denial of service",
            "volumetric",
            "http flood",
            "amplification",
            "scrubbing",
            "t1498",
            "gbps",
        ],
    ),
    (
        "Public S3 Bucket",
        [
            "s3",
            "public bucket",
            "allusers",
            "public access block",
            "object storage",
            "t1530",
            "bucket policy",
        ],
    ),
]

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_ASN_RE = re.compile(r"\bAS\d+\b", re.IGNORECASE)


def _walk_strings(obj: Any) -> list[str]:
    """Flatten nested JSON into string values for regex extraction."""
    out: list[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_walk_strings(v))
    elif isinstance(obj, list):
        for item in obj:
            out.extend(_walk_strings(item))
    elif isinstance(obj, str):
        out.append(obj)
    elif obj is not None:
        out.append(str(obj))
    return out


def _uniq(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def classify_attack(alert: dict[str, Any]) -> str:
    """Map alert content to an organizational playbook category."""
    blob = " ".join(_walk_strings(alert)).lower()
    scores: dict[str, int] = {}
    for label, keywords in _CLASSIFICATION_RULES:
        scores[label] = sum(1 for kw in keywords if re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", blob))
    best = max(scores, key=scores.get)
    winners = [label for label, score in scores.items() if score == scores[best]]
    return best if scores[best] > 0 and len(winners) == 1 else "Unknown"


def extract_iocs(alert: dict[str, Any]) -> dict[str, list[str]]:
    """Extract IoCs from structured hints and free-text fields."""
    iocs: dict[str, list[str]] = {
        "ips": [],
        "domains": [],
        "urls": [],
        "emails": [],
        "hashes": [],
        "asns": [],
        "filenames": [],
        "hostnames": [],
    }

    hint = alert.get("iocs_hint", {})
    if hint is None:
        hint = {}
    if not isinstance(hint, dict):
        raise ValueError("iocs_hint must be an object")
    for key in iocs:
        if key in hint and isinstance(hint[key], list):
            iocs[key].extend(str(x) for x in hint[key])

    blob = "\n".join(_walk_strings(alert))
    iocs["ips"].extend(_IPV4_RE.findall(blob))
    iocs["urls"].extend(_URL_RE.findall(blob))
    iocs["emails"].extend(_EMAIL_RE.findall(blob))
    iocs["hashes"].extend(_SHA256_RE.findall(blob))
    iocs["asns"].extend(_ASN_RE.findall(blob))

    # Domains from URLs + standalone domain regex (filter common noise)
    noise = {
        "example.com",
        "example.org",
        "acme-corp.com",
        "json",
        "exe",
        "txt",
    }
    for url in iocs["urls"]:
        try:
            host = urlsplit(url).hostname
        except ValueError:
            continue
        if host:
            try:
                ipaddress.ip_address(host)
                iocs["ips"].append(host)
            except ValueError:
                iocs["domains"].append(host.lower())
    for d in _DOMAIN_RE.findall(blob):
        dl = d.lower()
        if dl not in noise and not dl.endswith((".png", ".jpg", ".css", ".js", ".exe", ".dll", ".txt")):
            iocs["domains"].append(dl)

    def walk_fields(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key.lower() in ("hostname", "host", "computer_name") and isinstance(value, str):
                    iocs["hostnames"].append(value)
                if key.lower() in ("filename", "path", "process", "image", "file_path") and isinstance(value, str):
                    iocs["filenames"].append(PureWindowsPath(value).name)
                walk_fields(value)
        elif isinstance(obj, list):
            for value in obj:
                walk_fields(value)
    walk_fields(alert.get("raw_event") or {})
    # Recognize structured IPv6 addresses without interpreting arbitrary text as an IP.
    for value in _walk_strings(alert):
        try:
            iocs["ips"].append(str(ipaddress.ip_address(value)))
        except ValueError:
            pass

    return {k: _uniq(v) for k, v in iocs.items() if v}


def extract_cves(alert: dict[str, Any]) -> list[str]:
    blob = " ".join(_walk_strings(alert))
    return _uniq([c.upper() for c in _CVE_RE.findall(blob)])


def extract_mitre(alert: dict[str, Any]) -> list[str]:
    hints = alert.get("mitre_hint", [])
    if hints is None:
        hints = []
    if not isinstance(hints, list):
        raise ValueError("mitre_hint must be an array")
    found = [str(t).upper() for t in hints if re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(t), re.I)]
    blob = " ".join(_walk_strings(alert))
    found.extend(re.findall(r"T\d{4}(?:\.\d{3})?", blob, re.IGNORECASE))
    return _uniq([t.upper() if t.startswith("T") or t.startswith("t") else t for t in found])


def build_summary(alert: dict[str, Any], classification: str, iocs: dict[str, list[str]]) -> str:
    alert_id = alert.get("alert_id", "UNKNOWN")
    severity = alert.get("severity", "Unknown")
    rule = alert.get("rule_name", "")
    notes = alert.get("analyst_notes", "")
    ioc_bits = []
    for k, vals in iocs.items():
        if vals:
            ioc_bits.append(f"{k}={', '.join(vals[:3])}")
    ioc_str = "; ".join(ioc_bits) if ioc_bits else "none extracted"
    return (
        f"Alert {alert_id} ({severity}): classified as {classification}. "
        f"Rule: {rule}. IoCs: {ioc_str}. Notes: {notes}"
    )


def parse_alert(alert: dict[str, Any]) -> ParsedAlert:
    """Parse a raw JSON alert dict into structured fields."""
    if not isinstance(alert, dict):
        raise ValueError("Alert JSON must be an object")
    if not alert:
        raise ValueError("Alert object must not be empty")
    classification = classify_attack(alert)
    iocs = extract_iocs(alert)
    cves = extract_cves(alert)
    mitre = extract_mitre(alert)
    return ParsedAlert(
        alert_id=str(alert.get("alert_id", "UNKNOWN")),
        timestamp=str(alert.get("timestamp", "")),
        severity=str(alert.get("severity", "Unknown")),
        source=str(alert.get("source", "")),
        rule_name=str(alert.get("rule_name", "")),
        attack_classification=classification,
        mitre_techniques=mitre,
        iocs=iocs,
        related_cves=cves,
        summary=build_summary(alert, classification, iocs),
        raw=alert,
    )


def parse_alert_file(path: str | Path) -> ParsedAlert:
    path = Path(path)
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    return parse_alert(data)


def parse_alert_json_string(text: str) -> ParsedAlert:
    if len(text.encode("utf-8")) > 1_000_000:
        raise ValueError("Alert exceeds 1 MB limit")
    data = json.loads(text)
    return parse_alert(data)


def list_sample_alerts(alerts_dir: str | Path) -> list[Path]:
    alerts_dir = Path(alerts_dir)
    return sorted(alerts_dir.glob("alert_*.json"))
