import subprocess


def check_users():

    users = []

    with open("/etc/passwd", "r") as file:

        for line in file:

            parts = line.strip().split(":")

            if len(parts) >= 7:

                users.append({
                    "username": parts[0],
                    "uid": int(parts[2]),
                    "shell": parts[6]
                })

    return users


def check_services():

    services = []

    command = [
        "systemctl",
        "--type=service",
        "--state=running",
        "--no-pager",
        "--no-legend"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    for line in result.stdout.splitlines():

        parts = line.split()

        if len(parts) >= 1:

            services.append(parts[0])

    return services


def check_firewall():

    firewall = {
        "tool": None,
        "status": "Unknown",
        "observation": ""
    }

    # Check whether nft exists
    try:

        result = subprocess.run(
            ["which", "nft"],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:

            firewall["tool"] = "nftables"

            result = subprocess.run(
                ["sudo", "-n", "nft", "list", "ruleset"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:

                if result.stdout.strip():

                    firewall["status"] = "Configured"
                    firewall["observation"] = "nftables rules detected"

                else:

                    firewall["status"] = "Not configured"
                    firewall["observation"] = "No nftables rules detected"

            else:

                firewall["status"] = "Unknown"
                firewall["observation"] = (
                    "nftables detected but rules could not be read"
                )

            return firewall

    except subprocess.TimeoutExpired:

        firewall["tool"] = "nftables"
        firewall["status"] = "Unknown"
        firewall["observation"] = "Firewall check timed out"

        return firewall

    except FileNotFoundError:

        pass

    firewall["status"] = "Unknown"
    firewall["observation"] = (
        "No supported firewall tool detected"
    )

    return firewall


def audit_linux():

    result = {
        "users": check_users(),
        "password_policy": {},
        "file_permissions": {},
        "services": check_services(),
        "firewall": check_firewall()
    }

    return result


if __name__ == "__main__":

    result = audit_linux()

    print("\n========== LINUX SECURITY AUDIT ==========\n")

    print(result)
