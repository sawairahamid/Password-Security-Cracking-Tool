from datetime import datetime


def generate_report(password: str, strength: str, entropy: float, cracked: bool):
    """
    Generate a password security analysis report.
    Sensitive information is masked to ensure security.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    masked_password = "*" * len(password)

    try:
        with open("report.txt", "w") as report:
            report.write("PASSWORD SECURITY ANALYSIS REPORT\n")
            report.write("=" * 40 + "\n")
            report.write(f"Generated On     : {timestamp}\n\n")

            report.write(f"Password (Masked): {masked_password}\n")
            report.write(f"Password Length : {len(password)} characters\n")
            report.write(f"Strength Rating : {strength}\n")
            report.write(f"Entropy (bits)  : {entropy:.2f}\n")
            report.write(f"Cracked         : {'Yes' if cracked else 'No'}\n\n")

            report.write("Security Notes:\n")
            report.write("- Passwords must never be stored or logged in plain text.\n")
            report.write("- Higher entropy increases resistance against brute-force attacks.\n")
            report.write("- Use long, unique passwords for different services.\n")
            report.write("- Prefer password managers and multi-factor authentication.\n")

    except IOError:
        return "[✘] Failed to generate report"

    return "[✔] Security report generated successfully (report.txt)"
