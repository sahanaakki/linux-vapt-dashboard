from scanners.full_vapt import run_full_vapt

result = run_full_vapt("http://127.0.0.1:5000")

print("\n========== FULL VAPT RESULT ==========")
print("Scan ID:", result["scan_id"])
print("Target:", result["target"])

print("\n========== RISK SUMMARY ==========")
for severity, count in result["summary"].items():
    print(f"{severity}: {count}")

print("\n========== FINDINGS ==========")
for finding in result["findings"]:
    print(finding["severity"], "-", finding["title"])

print("\n========== SCANNER ERRORS ==========")
for error in result["errors"]:
    print(error)
