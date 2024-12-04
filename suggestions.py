insecure_to_secure = {
    "exec": "subprocess.run",
    "eval": "ast.literal_eval",
    "system": "subprocess.run",
    "strcpy": "strncpy",
    "gets": "fgets",
    # Add more mappings as needed
}


def suggest_fix(issue):
    if "Potential Vulnerability Detected" in issue["issue"]:
        return issue["suggestion"]
    for insecure_func in insecure_to_secure.keys():
        if insecure_func in issue["issue"]:
            secure_func = insecure_to_secure[insecure_func]
            return f"Replace '{insecure_func}' with '{secure_func}'"
    return "Refer to security best practices for remediation."
