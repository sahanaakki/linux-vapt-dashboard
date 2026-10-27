
import subprocess


def scan_network(target):
    """
    Scan a target using Nmap and return structured results.
    """

    command = [
        "nmap",
        "-sV",
        target
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result.stdout


if __name__ == "__main__":

    target = input("Enter target IP: ")

    output = scan_network(target)

    print("\n========== NMAP RESULT ==========\n")
    print(output)
