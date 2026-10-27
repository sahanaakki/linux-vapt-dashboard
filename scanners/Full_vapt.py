
from urllib.parse import urlparse

from scanners.network_scanner import scan_network
from scanners.web_scanner import scan_web
from scanners.linux_auditor import audit_linux

from analysis.risk_engine import analyze_findings
from database.db import create_database, save_scan, save_finding


def run_full_vapt(target):

    raw_findings = []
    errors = []

    # Accept either an IP address or a URL.
    target = target.strip()

    if "://" not in target:
        web_url = "http://" + target
    else:
        web_url = target

    parsed = urlparse(web_url)
    host = parsed.hostname

    if not host:
        raise ValueError("Please enter a valid IP address or URL.")

    create_database()

    # Save the scan before running the scanners.
    scan_id = save_scan(target, "Full VAPT")

    # --------------------------------
    # 1. NETWORK SCANNER
    # --------------------------------

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
                        "Verify whether this service is required."
                    ),
                    "evidence": f"Port {port}, service {service}",
                    "recommendation": (
                        "Disable Telnet if unnecessary. "
                        "Prefer SSH for remote administration."
                    )
                })

            elif port in [3306, 5432, 27017, 6379]:
                raw_findings.append({
                    "title": "Open Database",
                    "description": (
                        "A database service is reachable. "
                        "Verify that access is restricted."
                    ),
                    "evidence": f"Port {port}, service {service}",
                    "recommendation": (
                        "Restrict database access to trusted hosts "
                        "and require authentication."
                    )
                })

            elif port == 22:
                raw_findings.append({
                    "title": "Exposed SSH",
                    "description": (
                        "SSH is reachable. Exposure alone does not "
                        "prove a vulnerability; verify its configuration."
                    ),
                    "evidence": f"Port {port}, service {service}",
                    "recommendation": (
                        "Review SSH authentication, updates and "
                        "network access restrictions."
                    )
                })

    except Exception as error:
        errors.append(f"Network Scanner: {error}")

    # --------------------------------
    # 2. WEB SCANNER
    # --------------------------------

    try:
        web_result = scan_web(web_url)

        if web_result.get("error"):
            errors.append(
                f"Web Scanner: {web_result['error']}"
            )
        else:
            headers = web_result.get("security_headers", {})

            for header_name, title in [
                ("Strict-Transport-Security", "Missing HSTS"),
                ("Content-Security-Policy", "Missing CSP")
            ]:
                header_info = headers.get(header_name, {})

                if header_info.get("status") == "Missing":
                    raw_findings.append({
                        "title": title,
                        "description": (
                            f"{header_name} was not detected "
                            "in the HTTP response."
                        ),
                        "evidence": f"{header_name}: Missing",
                        "recommendation": (
                            f"Review whether {header_name} should "
                            "be configured for this website."
                        )
                    })

            for cookie in web_result.get("cookies", []):

                if not cookie.get("secure") or not cookie.get("httponly"):
                    raw_findings.append({
                        "title": "Insecure Cookie",
                        "description": (
                            "A cookie is missing the Secure or "
                            "HttpOnly attribute."
                        ),
                        "evidence": f"Cookie name: {cookie.get('name')}",
                        "recommendation": (
                            "Review the cookie's purpose and configure "
                            "Secure and HttpOnly where appropriate."
                        )
                    })

            if web_result.get("server"):
                raw_findings.append({
                    "title": "Information Disclosure",
                    "description": (
                        "The HTTP response includes a Server header."
                    ),
                    "evidence": (
                        f"Server: {web_result['server']}"
                    ),
                    "recommendation": (
                        "Consider minimizing unnecessary server "
                        "version information in HTTP responses."
                    )
                })

    except Exception as error:
        errors.append(f"Web Scanner: {error}")

    # --------------------------------
    # 3. LINUX SECURITY AUDITOR
    # --------------------------------

    try:
        linux_result = audit_linux()

        firewall = linux_result.get("firewall", {})

        if firewall.get("status") == "Not configured":
            raw_findings.append({
                "title": "Weak Firewall",
                "description": (
                    "The audit did not detect configured "
                    "nftables rules."
                ),
                "evidence": firewall.get(
                    "observation", "No rules detected"
                ),
                "recommendation": (
                    "Review the active firewall backend and configure "
                    "appropriate rules if required."
                )
            })

        elif firewall.get("status") == "Unknown":
            errors.append(
                "Linux Auditor: Firewall status could not be confirmed."
            )

    except Exception as error:
        errors.append(f"Linux Auditor: {error}")

    # --------------------------------
    # 4. RISK ENGINE
    # --------------------------------

    results = analyze_findings(raw_findings)

    # Preserve evidence and recommendations.
    for index, result in enumerate(results):
        result["evidence"] = raw_findings[index].get("evidence", "")
        result["recommendation"] = raw_findings[index].get(
            "recommendation", ""
        )

    # --------------------------------
    # 5. SAVE FINDINGS TO SQLITE
    # --------------------------------

    for finding in results:
        save_finding(
            scan_id,
            finding["title"],
            finding.get("description", ""),
            finding["severity"],
            finding.get("evidence", ""),
            finding.get("recommendation", "")
        )

    # --------------------------------
    # 6. RETURN RESULTS TO FLASK
    # --------------------------------

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

    return {
        "scan_id": scan_id,
        "target": target,
        "findings": results,
        "summary": summary,
        "errors": errors
    }
