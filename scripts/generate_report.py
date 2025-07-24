import json
import os

def map_severity(finding):
    # Use severity if present
    severity = finding.get("extra", {}).get("severity", "")
    if severity:
        return severity

    # Fallback: Infer severity from rule ID or message
    rule_id = finding.get("check_id", "").lower()
    message = finding.get("extra", {}).get("message", "").lower()

    if "xss" in message or "injection" in message:
        return "High"
    elif "plaintext" in message or "http" in message:
        return "Medium"
    elif "info" in message or "style" in message:
        return "Low"
    else:
        return "Unknown"

def severity_color(sev):
    return {
        "Critical": "🟣",
        "High": "🔴",
        "Medium": "🟠",
        "Low": "🟢",
        "Unknown": "⚪"
    }.get(sev, "⚪")

def main():
    input_file = "semgrep_report/semgrep.json"
    output_file = "semgrep_report/semgrep-report.html"

    with open(input_file, "r") as f:
        data = json.load(f)

    findings = data.get("results", [])
    total = len(findings)

    by_severity = {}
    for f in findings:
        sev = map_severity(f)
        by_severity.setdefault(sev, []).append(f)

    with open(output_file, "w") as f:
        f.write(f"<html><head><title>Semgrep Security Report</title></head><body>")
        f.write(f"<h2>🔍 Semgrep Security Report</h2>")
        f.write(f"<p>Total Findings: {total}</p><hr>")

        for sev in sorted(by_severity.keys(), reverse=True):
            color = severity_color(sev)
            count = len(by_severity[sev])
            f.write(f"<h3>{color} {sev} ({count})</h3><ul>")
            for finding in by_severity[sev]:
                eid = finding.get("check_id", "Unknown")
                msg = finding.get("extra", {}).get("message", "")
                path = finding.get("path", "")
                line = finding.get("start", {}).get("line", "")
                f.write(f"<li><b>[{eid}]</b> - {msg}<br>")
                f.write(f"<i>File:</i> {path} : <i>Line:</i> {line}</li><br><br>")
            f.write("</ul><hr>")

        f.write("</body></html>")

if __name__ == "__main__":
    main()
