
import sqlite3

from flask import Flask, render_template, request, redirect, url_for

from database.db import create_database, get_connection
from scanners.full_vapt import run_full_vapt

app = Flask(__name__)
create_database()


def get_risk_summary(findings):
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

    return summary


@app.route("/", methods=["GET", "POST"])
def dashboard():
    message = ""

    if request.method == "POST":
        target = request.form.get("target", "").strip()
        scan_type = request.form.get("scan_type", "").strip()

        allowed_types = ["Network", "Web", "Linux", "Full"]

        if not target:
            message = "Please enter a target."

        elif scan_type not in allowed_types:
            message = "Please select a valid scan type."

        elif (
            scan_type == "Linux"
            and target not in ["localhost", "127.0.0.1"]
        ):
            message = "Linux Audit is for this machine only."

        elif scan_type == "Full":
            try:
                result = run_full_vapt(target)

                for error in result.get("errors", []):
                    print(error)

                return redirect(
                    url_for("results", scan_id=result["scan_id"])
                )

            except Exception as error:
                message = f"Full VAPT scan failed: {error}"
                print(message)

        else:
            message = (
                f"{scan_type} scan integration is not connected yet."
            )

    connection = get_connection()
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # Get the latest scan.
    cursor.execute("""
        SELECT *
        FROM scans
        ORDER BY scan_id DESC
        LIMIT 1
    """)
    latest_scan = cursor.fetchone()

    findings = []

    if latest_scan:
        cursor.execute("""
            SELECT title, description, severity,
                   evidence, recommendation
            FROM findings
            WHERE scan_id = ?
        """, (latest_scan["scan_id"],))

        findings = [dict(row) for row in cursor.fetchall()]

    summary = get_risk_summary(findings)

    # Get the finding count for every saved scan.
    cursor.execute("""
        SELECT
            s.scan_id,
            s.date,
            s.scan_type,
            s.target,
            COUNT(f.finding_id) AS finding_count
        FROM scans AS s
        LEFT JOIN findings AS f
            ON s.scan_id = f.scan_id
        GROUP BY
            s.scan_id, s.date, s.scan_type, s.target
        ORDER BY s.scan_id ASC
    """)

    scan_history = [
        dict(row) for row in cursor.fetchall()
    ]

    connection.close()

    return render_template(
        "index.html",
        message=message,
        latest_scan=latest_scan,
        summary=summary,
        findings=findings,
        scan_history=scan_history
    )


@app.route("/results/<int:scan_id>")
def results(scan_id):
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM scans WHERE scan_id = ?",
        (scan_id,)
    )
    scan = cursor.fetchone()

    if scan is None:
        connection.close()
        return "Scan not found.", 404

    cursor.execute("""
        SELECT title, description, severity,
               evidence, recommendation
        FROM findings
        WHERE scan_id = ?
        ORDER BY finding_id ASC
    """, (scan_id,))

    findings = [dict(row) for row in cursor.fetchall()]
    connection.close()

    summary = get_risk_summary(findings)

    return render_template(
        "results.html",
        scan=scan,
        findings=findings,
        summary=summary
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
 
