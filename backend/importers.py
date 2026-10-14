"""Normalize scanner-authored reports. Imports remain explicitly unverified."""
import json
import xml.etree.ElementTree as ET

SEVERITIES = {"critical", "high", "medium", "low", "info"}


def finding(title, severity, rule, target, detail, remediation="Review the scanner evidence and apply the vendor-recommended mitigation."):
    sev = str(severity).lower()
    sev = {"warning": "medium", "error": "high", "informational": "info", "unknown": "info"}.get(sev, sev)
    return {"title": str(title)[:300], "severity": sev if sev in SEVERITIES else "info", "rule_id": str(rule), "target": str(target), "description": str(detail)[:20000], "remediation": str(remediation)[:10000]}


def parse_report(scanner, content):
    rows = []
    if scanner == "nmap":
        if "<!DOCTYPE" in content.upper() or "<!ENTITY" in content.upper():
            raise ValueError("XML document types/entities are not accepted")
        root = ET.fromstring(content)
        if root.tag != "nmaprun":
            raise ValueError("Expected an Nmap XML report")
        for host in root.findall("host"):
            address = host.find("address")
            target = address.get("addr", "") if address is not None else ""
            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                name = service.get("name", "unknown") if service is not None else "unknown"
                number = port.get("portid")
                rows.append(finding(f"Open {port.get('protocol')}/{number} · {name}", "info", f"port:{number}/{port.get('protocol')}", target, ET.tostring(port, encoding="unicode"), "Confirm this service is required and restrict network access. An open port alone is not a vulnerability."))
        return rows
    if scanner == "nuclei":
        try:
            payload = json.loads(content)
            data = payload if isinstance(payload, list) else [payload]
        except json.JSONDecodeError:
            data = [json.loads(line) for line in content.splitlines() if line.strip()]
        for x in data:
            if not x.get("template-id") or not isinstance(x.get("info"), dict):
                raise ValueError("Expected Nuclei JSON or JSONL findings")
            info = x["info"]
            rows.append(finding(info.get("name", x["template-id"]), info.get("severity", "info"), x["template-id"], x.get("matched-at", x.get("host", "")), info.get("description", "") + "\n" + json.dumps(x.get("extracted-results", []))))
        return rows
    data = json.loads(content)
    if scanner == "semgrep":
        if "results" not in data:
            raise ValueError("Expected Semgrep results")
        for x in data["results"]:
            e = x.get("extra", {})
            rows.append(finding(e.get("message", x["check_id"]), e.get("severity", "info"), x["check_id"], f"{x.get('path', '')}:{x.get('start', {}).get('line', '')}", e.get("lines", e.get("message", "")), e.get("fix", "Review the rule guidance and correct the affected source.")))
    elif scanner == "trivy":
        if "Results" not in data:
            raise ValueError("Expected Trivy Results")
        for group in data["Results"] or []:
            for x in group.get("Vulnerabilities", []) or []:
                rows.append(finding(f"{x['VulnerabilityID']} · {x.get('PkgName', '')}", x.get("Severity", "info"), x["VulnerabilityID"] + ":" + x.get("PkgName", ""), group.get("Target", ""), x.get("Description", x.get("Title", "")), f"Installed: {x.get('InstalledVersion', 'unknown')}. Fixed version: {x.get('FixedVersion') or 'No fixed version reported'}"))
    elif scanner == "zap":
        if "site" not in data:
            raise ValueError("Expected ZAP JSON with site array")
        for site in data["site"]:
            for x in site.get("alerts", []):
                rows.append(finding(x.get("name", x.get("alert", "ZAP alert")), {"0": "info", "1": "low", "2": "medium", "3": "high"}.get(str(x.get("riskcode")), "info"), x.get("pluginid", x.get("alertRef", "zap")), site.get("@name", ""), x.get("desc", "") + "\n" + json.dumps(x.get("instances", [])), x.get("solution", "Review alert guidance.")))
    else:
        raise ValueError("Unsupported scanner report format")
    return rows
