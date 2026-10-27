
from urllib.parse import urlparse

from scanners.network_scanner import scan_network
from scanners.web_scanner import scan_web
from scanners.linux_auditor import audit_linux

from analysis.risk_engine import analyze_findings
from database.db import create_database, save_scan, save_finding


def run_full_vapt(target):
    target = target.strip()

    if not target:
        raise ValueError("Please enter a target.")

    # Prepare the target URL.
    if "://" not in target:
        web_url = "http://" + target
    else:
        web_url = target

    parsed = urlparse(web_url)
    host = parsed.hostname

    if not host:
        raise ValueError("Please enter a valid IP address or URL.")

    raw_findings = []
    errors = []

    # Create database and record this scan.
    create_database()
    scan_id = save_scan(target, "Full VAPT")

    # --------------------------------------------------
    # 1. NETWORK SCANNER
    # --------------------------------------------------
    try:
        network_result = scan_network(host)

        for port_info in network_result.get("ports", []):
            if port_info.get("state") != "open":
                continue

            port = port_info.get("port")
            service = port_info.get("service", "unknown")

            if port == 23:
                raw_findings.append({
                    "title": "Exposed Telnet",
                    "description": (
                        "Telnet is reachable on the target. "
                        "Verify whether the service is required."
                    ),
                    "evidence": (
                        f"Target: {host}; Port: {port}; "
                        f"State: open; Service: {service}"
                    ),
                    "recommendation": (
                        "Disable Telnet if it is unnecessary. "
                        "Prefer secure remote administration methods."
                    )
                })

            elif port in [3306, 5432, 27017, 6379]:
                raw_findings.append({
                    "title": "Open Database",
                    "description": (
                        "A database-related port is reachable. "
                        "This alone does not prove unauthorized access."
                    ),
                    "evidence": (
                        f"Target: {host}; Port: {port}; "
                        f"State: open; Service: {service}"
                    ),
                    "recommendation": (
                        "Restrict database access to trusted systems "
                        "and verify authentication and firewall rules."
                    )
                })

            elif port == 22:
                raw_findings.append({
                    "title": "Exposed SSH",
                    "description": (
                        "SSH is reachable. Confirm that its exposure "
                        "is intended and appropriately secured."
                    ),
                    "evidence": (
                        f"Target: {host}; Port: {port}; "
                        f"State: open; Service: {service}"
                    ),
                    "recommendation": (
                        "Review SSH configuration, authentication, "
                        "software updates and access restrictions."
                    )
                })

    except Exception as error:
        errors.append(f"Network Scanner: {error}")

    # --------------------------------------------------
    # 2. WEB SCANNER
    # --------------------------------------------------
    try:
        web_result = scan_web(web_url)

        if web_result.get("error"):
            errors.append(
                f"Web Scanner: {web_result['error']}"
            )

        else:
            headers = web_result.get("security_headers", {})
            status_code = web_result.get("status_code")
            actual_url = web_result.get("url", web_url)

            headers_to_check = [
                (
                    "Strict-Transport-Security",
                    "Missing HSTS",
                    "MEDIUM"
                ),
                (
                    "Content-Security-Policy",
                    "Missing CSP",
                    "MEDIUM"
                ),
                (
                    "X-Content-Type-Options",
                    "Missing X-Content-Type-Options",
                    "LOW"
                )
            ]

            for header_name, title, severity_hint in headers_to_check:
                header_info = headers.get(header_name, {})

                if header_info.get("status") == "Missing":
                    raw_findings.append({
                        "title": title,
                        "description": (
                            f"The HTTP response did not contain "
                            f"the {header_name} header."
                        ),
                        "evidence": (
                            f"URL: {actual_url}; "
                            f"HTTP status: {status_code}; "
                            f"Header checked: {header_name}; "
                            f"Observed result: Missing"
                        ),
                        "recommendation": (
                            f"Review the website's security requirements "
                            f"and configure {header_name} where appropriate."
                        )
                    })

            # Inspect cookie security attributes.
            for cookie in web_result.get("cookies", []):
                missing_flags = []

                if not cookie.get("secure"):
                    missing_flags.append("Secure")

                if not cookie.get("httponly"):
                    missing_flags.append("HttpOnly")

                if missing_flags:
                    raw_findings.append({
                        "title": "Insecure Cookie",
                        "description": (
                            "A cookie is missing one or more "
                            "recommended security attributes."
                        ),
                        "evidence": (
                            f"URL: {actual_url}; "
                            f"Cookie name: {cookie.get('name')}; "
                            f"Secure: {cookie.get('secure')}; "
                            f"HttpOnly: {cookie.get('httponly')}; "
                            f"Missing attributes: {', '.join(missing_flags)}"
                        ),
                        "recommendation": (
                            "Review the cookie's purpose and configure "
                            "Secure and HttpOnly where appropriate."
                        )
                    })

            # Record the Server header as an observation.
            server = web_result.get("server")

            if server:
                raw_findings.append({
                    "title": "Information Disclosure",
                    "description": (
                        "The response includes a Server header. "
                        "This does not necessarily expose a vulnerability."
                    ),
                    "evidence": (
                        f"URL: {actual_url}; "
                        f"Server header: {server}"
                    ),
                    "recommendation": (
                        "Review whether the server header reveals "
                        "unnecessary implementation or version details."
                    )
                })

    except Exception as error:
        errors.append(f"Web Scanner: {error}")

    # --------------------------------------------------
    # 3. LINUX SECURITY AUDITOR
    # --------------------------------------------------
    try:
        linux_result = audit_linux()
        firewall = linux_result.get("firewall", {})

        if firewall.get("status") == "Not configured":
            raw_findings.append({
                "title": "Weak Firewall",
                "description": (
                    "The audit did not detect configured nftables rules. "
                    "Other firewall mechanisms may still be present."
                ),
                "evidence": (
                    firewall.get(
                        "observation",
                        "No nftables rules detected"
                    )
                ),
                "recommendation": (
                    "Review the active firewall backend and configure "
                    "appropriate filtering rules if required."
                )
            })

        elif firewall.get("status") == "Unknown":
            errors.append(
                "Linux Auditor: Firewall status could not be confirmed."
            )

    except Exception as error:
        errors.append(f"Linux Auditor: {error}")

    # --------------------------------------------------
    # 4. RISK ANALYSIS
    # --------------------------------------------------
    results = analyze_findings(raw_findings)

    # Match each analyzed finding with its collected evidence.
    for index, finding in enumerate(results):
        original = raw_findings[index]

        finding["evidence"] = original.get("evidence", "")
        finding["recommendation"] = original.get(
            "recommendation", ""
        )

    # --------------------------------------------------
    # 5. SAVE FINDINGS TO SQLITE DATABASE
    # --------------------------------------------------
    for finding in results:
        save_finding(
            scan_id,
            finding.get("title", "Untitled finding"),
            finding.get("description", ""),
            finding.get("severity", "INFO"),
            finding.get("evidence", ""),
            finding.get("recommendation", "")
        )

    # --------------------------------------------------
    # 6. CREATE RISK SUMMARY
    # --------------------------------------------------
    summary = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for finding in results:
        severity = finding.get("severity", "INFO")

        if severity in summary:
            summary[severity] += 1

    # Return results to the dashboard.
    return {
        "scan_id": scan_id,
        "target": target,
        "findings": results,
        "summary": summary,
        "errors": errors
    }


if __name__ == "__main__":
    test_target = input(
        "Enter an authorized test IP or URL: "
    ).strip()

    try:
        result = run_full_vapt(test_target)

        print("\n========== FULL VAPT RESULTS ==========")
        print("Scan ID:", result["scan_id"])
        print("Target:", result["target"])

        print("\n========== RISK SUMMARY ==========")
        for severity, count in result["summary"].items():
            print(f"{severity}: {count}")

        print("\n========== FINDINGS ==========")
        for finding in result["findings"]:
            print("\nFinding:", finding["title"])
            print("Severity:", finding["severity"])
            print("Description:", finding["description"])
            print("Evidence:", finding["evidence"])
            print("Recommendation:", finding["recommendation"])
            print("-" * 45)

        print("\n========== SCANNER ERRORS ==========")
        if result["errors"]:
            for error in result["errors"]:
                print(error)
        else:
            print("No scanner errors reported.")

    except Exception as error:
        print("Full VAPT scan failed:", error)

