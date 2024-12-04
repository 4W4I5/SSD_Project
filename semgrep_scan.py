# semgrep_scan.py
import subprocess
import json
import os


def run_semgrep_scan(filepath):
    try:
        result = subprocess.run(
            ["semgrep", "--config", "auto", filepath, "--json"],
            capture_output=True,
            text=True,
        )
        semgrep_output = result.stdout

        # Handle exit codes
        if result.returncode in [0, 1]:
            semgrep_results = json.loads(semgrep_output)
        else:
            return [
                {
                    "issue": f"Semgrep execution error (exit code {result.returncode})",
                    "severity": "ERROR",
                    "line_number": "N/A",
                    "suggestion": "Semgrep failed to execute properly.",
                }
            ]

        findings = []
        # Include errors if any
        errors = semgrep_results.get("errors", [])
        for error in errors:
            finding = {
                "issue": f"Semgrep Error: {error.get('message', 'Unknown error')}",
                "severity": "ERROR",
                "filename": error.get("path", "Unknown file"),
                "line_number": error.get("start", {}).get("line", "N/A"),
                "suggestion": "Check the file syntax and ensure it is valid code.",
            }
            findings.append(finding)

        # Process actual results
        for result_item in semgrep_results.get("results", []):
            finding = {
                "issue": result_item.get("check_id", "No description"),
                "severity": result_item.get("extra", {}).get("severity", "UNKNOWN"),
                "line_number": result_item.get("start", {}).get("line", "N/A"),
                "suggestion": result_item.get("extra", {}).get(
                    "message", "No suggestion provided."
                ),
            }
            findings.append(finding)
        return findings

    except subprocess.CalledProcessError as e:
        print(f"Semgrep scan failed: {e}")
        return [
            {
                "issue": "Semgrep failed to run",
                "severity": "ERROR",
                "line_number": "N/A",
                "suggestion": f"Semgrep execution failed with error: {e}",
            }
        ]
    except FileNotFoundError:
        print("Semgrep is not installed or not found in PATH.")
        return [
            {
                "issue": "Semgrep not installed",
                "severity": "ERROR",
                "line_number": "N/A",
                "suggestion": "Please install Semgrep to run security scans.",
            }
        ]
    except json.JSONDecodeError as e:
        print(f"Failed to parse Semgrep output: {e}")
        return [
            {
                "issue": "Failed to parse Semgrep output",
                "severity": "ERROR",
                "line_number": "N/A",
                "suggestion": f"Semgrep output could not be parsed as JSON: {e}",
            }
        ]
