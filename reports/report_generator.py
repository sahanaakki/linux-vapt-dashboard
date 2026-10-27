
import os
import sqlite3
from html import escape
from datetime import datetime

DATABASE = "database/vapt.db"
REPORT_DIRECTORY = "reports/generated"


def generate_report(scan_id):
    # Check that the database exists.
    if not os.path.exists(DATABASE):
        raise FileNotFoundError(
            f"Database not found: {DATABASE}"
        )

    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # Get scan details.
    cursor.execute(
        "SELECT * FROM scans WHERE scan_id = ?",
        (scan_id,)
    )
    scan = cursor.fetchone()

    if scan is None:
        connection.close()
        raise ValueError(f"Scan ID {scan_id} was not found.")

    # Get findings belonging to this scan.
    cursor.execute(
        """
        SELECT title, description, severity,
               evidence, recommendation
        FROM findings
        WHERE scan_id = ?
        ORDER BY finding_id ASC
        """,
        (scan_id,)
    )
    findings = [dict(row) for row in cursor.fetchall()]
    connection.close()

    # Calculate severity totals.
    summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for finding in findings:
        severity = finding.get("severity", "INFO")
        if severity in summary:
            summary[severity] += 1

    # Create the output directory.
    os.makedirs(REPORT_DIRECTORY, exist_ok=True)

    filename = f"vapt_report_{scan_id}.html"
    filepath = os.path.join(REPORT_DIRECTORY, filename)

    # Escape database values before inserting them into HTML.
    target = escape(str(scan["target"]))
    scan_type = escape(str(scan["scan_type"]))
    scan_date = escape(str(scan["date"]))
    scan_time = escape(str(scan["time"]))

    finding_sections = ""

    if findings:
        for number, finding in enumerate(findings, start=1):
            title = escape(str(finding.get("title") or "Untitled"))
            severity = escape(
                str(finding.get("severity") or "INFO")
            )
            description = escape(
                str(finding.get("description") or "Not provided")
            )
            evidence = escape(
                str(finding.get("evidence") or "No evidence recorded")
            )
            recommendation = escape(
                str(
                    finding.get("recommendation")
                    or "Review and investigate this finding."
                )
            )

            finding_sections += f"""
            <section class="finding">
                <h2>{number}. {title}</h2>
                <p><strong>Severity:</strong>
                   <span class="severity">{severity}</span>
                </p>
                <h3>Description</h3>
                <p>{description}</p>
                <h3>Evidence</h3>
                <pre>{evidence}</pre>
                <h3>Recommendation</h3>
                <p>{recommendation}</p>
            </section>
            """
    else:
        finding_sections = """
        <p>No findings were recorded for this scan.
        This does not guarantee that the target is secure.</p>
        """

    generated_time = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VAPT Report - Scan {scan_id}</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #f3f5f9;
    color: #202938;
    margin: 0;
    padding: 24px;
}}
main {{
    max-width: 900px;
    margin: auto;
    background: white;
    padding: 28px;
    border-radius: 10px;
}}
h1 {{ color: #17356b; }}
.summary {{
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
}}
.count {{
    padding: 16px 8px;
    background: #eef2f7;
    text-align: center;
    border-radius: 8px;
}}
.count strong {{
    display: block;
    font-size: 26px;
    margin-bottom: 8px;
}}
.finding {{
    border-top: 1px solid #d7dce5;
    padding: 20px 0;
    overflow-wrap: anywhere;
}}
pre {{
    white-space: pre-wrap;
    overflow-wrap: anywhere;
    background: #f3f5f9;
    padding: 12px;
    border-radius: 6px;
}}
button {{
    padding: 10px 16px;
    border: 0;
    border-radius: 6px;
    background: #17356b;
    color: white;
    cursor: pointer;
}}
.high {{ color: #b42318; }}
.medium {{ color: #a15c00; }}
.low {{ color: #2367b2; }}
.info {{ color: #596579; }}
@media print {{
    body {{ background: white; padding: 0; }}
    main {{ box-shadow: none; padding: 0; }}
    button {{ display: none; }}
}}
@media (max-width: 600px) {{
    body {{ padding: 10px; }}
    main {{ padding: 16px; }}
    .summary {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
}}
</style>
</head>
<body>
<main>
    <button onclick="window.print()">Print / Save as PDF</button>

    <h1>Vulnerability Assessment and Penetration Testing Report</h1>
    <p><strong>Scan ID:</strong> {scan_id}</p>
    <p><strong>Target:</strong> {target}</p>
    <p><strong>Scan Type:</strong> {scan_type}</p>
    <p><strong>Scan Date:</strong> {scan_date}</p>
    <p><strong>Scan Time:</strong> {scan_time}</p>

    <hr>
    <h2>Risk Summary</h2>
    <div class="summary">
        <div class="count high">
            <strong>{summary["HIGH"]}</strong>HIGH
        </div>
        <div class="count medium">
            <strong>{summary["MEDIUM"]}</strong>MEDIUM
        </div>
        <div class="count low">
            <strong>{summary["LOW"]}</strong>LOW
        </div>
        <div class="count info">
            <strong>{summary["INFO"]}</strong>INFO
        </div>
    </div>

    <h2>Detailed Findings</h2>
    {finding_sections}

    <hr>
    <p><strong>Report generated:</strong> {generated_time}</p>
    <p>Generated by the Linux-Based Automated Web &amp; Network VAPT Dashboard.</p>
    <p>Findings reflect the checks performed and should be verified before remediation decisions.</p>
</main>
</body>
</html>
"""

    with open(filepath, "w", encoding="utf-8") as report_file:
        report_file.write(report_html)

    return os.path.abspath(filepath)


if __name__ == "__main__":
    try:
        scan_id = int(input("Enter the Scan ID: "))
        report_path = generate_report(scan_id)
        print("\nReport generated successfully!")
        print("Report location:", report_path)
    except (ValueError, FileNotFoundError, sqlite3.Error) as error:
        print("Could not generate report:", error)
