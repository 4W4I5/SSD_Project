# bandit_scan.py
import subprocess
import json


def run_bandit_scan(filepath):
    try:
        result = subprocess.run(
            ["bandit", "-r", filepath, "-f", "json"],
            capture_output=True,
            text=True,
            # Removed check=True to handle non-zero exit codes manually
        )
        bandit_output = result.stdout

        # Check if Bandit execution resulted in an error
        if result.returncode == 2:
            # Bandit execution error
            return [
                {
                    "issue": "Bandit execution error",
                    "severity": "ERROR",
                    "line_number": "N/A",
                    "suggestion": "Bandit failed to execute properly.",
                }
            ]

        # Proceed to process the output even if exit code is 1 (issues found)
        bandit_results = json.loads(bandit_output)

        findings = []
        # Include errors if any
        errors = bandit_results.get("errors", [])
        for error in errors:
            finding = {
                "issue": f"Bandit Error: {error.get('reason', 'Unknown error')}",
                "severity": "ERROR",
                "filename": error.get("filename", "Unknown file"),
                "line_number": "N/A",
                "suggestion": "Check the file syntax and ensure it is valid Python code.",
            }
            findings.append(finding)

        # Process actual results
        for issue in bandit_results.get("results", []):
            finding = {
                "issue": issue.get("issue_text", "No description"),
                "severity": issue.get("issue_severity", "UNKNOWN"),
                "line_number": issue.get("line_number", "N/A"),
                "suggestion": "Refer to Bandit documentation for remediation steps.",
            }
            findings.append(finding)

        return findings

    except subprocess.CalledProcessError as e:
        # Handle unexpected subprocess errors
        print(f"Bandit scan failed: {e}")
        return [
            {
                "issue": "Bandit failed to run",
                "severity": "ERROR",
                "line_number": "N/A",
                "suggestion": f"Bandit execution failed with error: {e}",
            }
        ]
    except FileNotFoundError:
        print("Bandit is not installed or not found in PATH.")
        return [
            {
                "issue": "Bandit not installed",
                "severity": "ERROR",
                "line_number": "N/A",
                "suggestion": "Please install Bandit to run security scans.",
            }
        ]
    except json.JSONDecodeError as e:
        print(f"Failed to parse Bandit output: {e}")
        return [
            {
                "issue": "Failed to parse Bandit output",
                "severity": "ERROR",
                "line_number": "N/A",
                "suggestion": f"Bandit output could not be parsed as JSON: {e}",
            }
        ]
