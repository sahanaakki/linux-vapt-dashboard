def calculate_severity(finding):

    title = finding.get("title", "").lower()

    # -----------------------------
    # Web Security Findings
    # -----------------------------

    if "insecure http" in title:
        return "HIGH"

    elif "missing hsts" in title:
        return "MEDIUM"

    elif "missing csp" in title:
        return "MEDIUM"

    elif "insecure cookie" in title:
        return "MEDIUM"

    # -----------------------------
    # Network Security Findings
    # -----------------------------

    elif "exposed ssh" in title:
        return "MEDIUM"

    elif "exposed telnet" in title:
        return "HIGH"

    elif "open database" in title:
        return "HIGH"

    # -----------------------------
    # Linux Security Findings
    # -----------------------------

    elif "weak firewall" in title:
        return "MEDIUM"

    elif "no firewall" in title:
        return "MEDIUM"

    elif "weak file permission" in title:
        return "HIGH"

    elif "weak password policy" in title:
        return "MEDIUM"

    # -----------------------------
    # Information Disclosure
    # -----------------------------

    elif "information disclosure" in title:
        return "LOW"

    # -----------------------------
    # Unknown Finding
    # -----------------------------
     
    elif "missing x-content-type-options" in title:
        return "LOW"

    else:
        return "INFO"


def analyze_findings(findings):

    results = []

    for finding in findings:

        severity = calculate_severity(finding)

        result = {
            "title": finding.get("title"),
            "description": finding.get("description"),
            "severity": severity
        }

        results.append(result)

    return results


def generate_summary(results):

    summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for result in results:

        severity = result["severity"]

        if severity in summary:
            summary[severity] += 1

    return summary


# -----------------------------
# Test Risk Engine
# -----------------------------

if __name__ == "__main__":

    test_findings = [

        {
            "title": "Insecure HTTP",
            "description": "Website is using HTTP instead of HTTPS."
        },

        {
            "title": "Missing HSTS",
            "description": "Strict-Transport-Security header is missing."
        },

        {
            "title": "Missing CSP",
            "description": "Content-Security-Policy header is missing."
        },

        {
            "title": "Exposed Telnet",
            "description": "Telnet service is accessible."
        },

        {
            "title": "Open Database",
            "description": "Database service is exposed."
        },

        {
            "title": "Weak Firewall",
            "description": "Firewall rules are not properly configured."
        },

        {
            "title": "Information Disclosure",
            "description": "Server information is exposed."
        }
    ]

    results = analyze_findings(test_findings)

    print("\n========== RISK ANALYSIS ==========\n")

    for result in results:

        print("Finding:", result["title"])
        print("Severity:", result["severity"])
        print("Description:", result["description"])
        print("--------------------------------")

    summary = generate_summary(results)

    print("\n========== RISK SUMMARY ==========\n")

    print("HIGH:", summary["HIGH"])
    print("MEDIUM:", summary["MEDIUM"])
    print("LOW:", summary["LOW"])
    print("INFO:", summary["INFO"])
