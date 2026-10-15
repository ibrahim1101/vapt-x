"""Normalize scanner-authored observations; provenance is assigned by the caller."""
import json
import re
import xml.etree.ElementTree as ET

SEVERITIES = {"critical", "high", "medium", "low", "info"}
MAX_REPORT_BYTES = 2_000_000
MAX_FINDINGS = 2000


def finding(title, severity, rule, target, detail, remediation="Review the scanner evidence and apply the vendor-recommended mitigation."):
    sev = str(severity).lower()
    sev = {"warning": "medium", "error": "high", "informational": "info", "unknown": "info"}.get(sev, sev)
    return {"cve_ids": sorted(set(re.findall(r"\bCVE-\d{4}-\d{4,19}\b", f"{title} {rule} {detail}".upper())))[:20], "cwe_ids": sorted(set(re.findall(r"\bCWE-\d{1,6}\b", f"{title} {rule} {detail}".upper())))[:30], "title": str(title)[:300], "severity": sev if sev in SEVERITIES else "info", "rule_id": str(rule), "target": str(target), "description": str(detail)[:20000], "remediation": str(remediation)[:10000]}


def _object(value, label):
    if not isinstance(value, dict):
        raise ValueError(f"Expected {label} object")
    return value


def _array(value, label, nullable=False):
    if value is None and nullable:
        return []
    if not isinstance(value, list):
        raise ValueError(f"Expected {label} array")
    return value


def _text(value, label, default=""):
    if value is None:
        return default
    if not isinstance(value, str):
        raise ValueError(f"Expected {label} text")
    return value


def _required(value, label):
    text = _text(value, label)
    if not text.strip():
        raise ValueError(f"Missing {label}")
    return text


def _json(content):
    try:
        return json.loads(content)
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("Invalid JSON report") from None


def parse_report(scanner, content):
    if scanner not in {"nmap", "nuclei", "semgrep", "trivy", "zap"}:
        raise ValueError("Unsupported scanner report format")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Report must contain text")
    if len(content.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("Maximum report size is 2 MB")
    rows = []

    def append(row):
        if len(rows) >= MAX_FINDINGS:
            raise ValueError("Maximum 2,000 findings per import")
        rows.append(row)

    if scanner == "nmap":
        # Nmap emits this inert declaration. Never accept a subset, entity or URL.
        xml = re.sub(r"<!DOCTYPE\s+nmaprun\s*>", "", content)
        if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
            raise ValueError("XML external declarations and entities are not accepted")
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            raise ValueError("Invalid Nmap XML report") from None
        if root.tag != "nmaprun":
            raise ValueError("Expected an Nmap XML report")
        for host in root.findall("host"):
            address = next((a for a in host.findall("address") if a.get("addrtype") in {"ipv4", "ipv6"}), None)
            if address is None:
                address = host.find("address")
            target = address.get("addr", "") if address is not None else ""
            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                number, protocol = port.get("portid", ""), port.get("protocol", "")
                if not number.isascii() or not number.isdigit() or not 1 <= int(number) <= 65535 or protocol not in {"tcp", "udp", "sctp"}:
                    raise ValueError("Invalid Nmap port or protocol")
                _required(target, "Nmap host address")
                service = port.find("service")
                name = service.get("name", "unknown") if service is not None else "unknown"
                append(finding(f"Open {protocol}/{number} · {name}", "info", f"port:{number}/{protocol}", target, ET.tostring(port, encoding="unicode"), "Confirm this service is required and restrict network access. An open port alone is not a vulnerability."))
        return rows
    if scanner == "nuclei":
        try:
            payload = _json(content)
            data = payload if isinstance(payload, list) else [payload]
        except ValueError:
            data = [_json(line) for line in content.splitlines() if line.strip()]
        for item in data:
            x = _object(item, "Nuclei finding")
            rule = _required(x.get("template-id"), "Nuclei template-id")
            info = _object(x.get("info"), "Nuclei info")
            detail = _text(info.get("description"), "Nuclei description")
            extracted = _array(x.get("extracted-results", []), "Nuclei extracted-results", nullable=True)
            append(finding(_text(info.get("name"), "Nuclei name", rule), info.get("severity", "info"), rule, _text(x.get("matched-at", x.get("host")), "Nuclei target"), detail + "\n" + json.dumps(extracted)))
        return rows
    data = _object(_json(content), f"{scanner} report")
    if scanner == "semgrep":
        for item in _array(data.get("results"), "Semgrep results"):
            x = _object(item, "Semgrep result")
            rule = _required(x.get("check_id"), "Semgrep check_id")
            e = _object(x.get("extra", {}), "Semgrep extra")
            start = _object(x.get("start", {}), "Semgrep start")
            path = _text(x.get("path"), "Semgrep path")
            message = _text(e.get("message"), "Semgrep message", rule)
            append(finding(message, e.get("severity", "info"), rule, f"{path}:{start.get('line', '')}", _text(e.get("lines"), "Semgrep lines", message), _text(e.get("fix"), "Semgrep fix", "Review the rule guidance and correct the affected source.")))
    elif scanner == "trivy":
        if "Results" not in data:
            raise ValueError("Expected Trivy Results array")
        for item in _array(data["Results"], "Trivy Results", nullable=True):
            group = _object(item, "Trivy result")
            for item in _array(group.get("Vulnerabilities", []), "Trivy Vulnerabilities", nullable=True):
                x = _object(item, "Trivy vulnerability")
                rule = _required(x.get("VulnerabilityID"), "Trivy VulnerabilityID")
                package = _text(x.get("PkgName"), "Trivy PkgName")
                append(finding(f"{rule} · {package}", x.get("Severity", "info"), rule + ":" + package, _text(group.get("Target"), "Trivy Target"), _text(x.get("Description"), "Trivy Description", _text(x.get("Title"), "Trivy Title")), f"Installed: {x.get('InstalledVersion') or 'unknown'}. Fixed version: {x.get('FixedVersion') or 'No fixed version reported'}"))
    elif scanner == "zap":
        for item in _array(data.get("site"), "ZAP site"):
            site = _object(item, "ZAP site")
            for item in _array(site.get("alerts", []), "ZAP alerts"):
                x = _object(item, "ZAP alert")
                rule = x.get("pluginid", x.get("alertRef"))
                if isinstance(rule, int) and not isinstance(rule, bool):
                    rule = str(rule)
                rule = _required(rule, "ZAP pluginid/alertRef")
                desc = _text(x.get("desc"), "ZAP desc")
                instances = _array(x.get("instances", []), "ZAP instances", nullable=True)
                append(finding(_text(x.get("name", x.get("alert")), "ZAP name", "ZAP alert"), {"0": "info", "1": "low", "2": "medium", "3": "high"}.get(str(x.get("riskcode")), "info"), rule, _text(site.get("@name"), "ZAP site name"), desc + "\n" + json.dumps(instances), _text(x.get("solution"), "ZAP solution", "Review alert guidance.")))
    return rows
