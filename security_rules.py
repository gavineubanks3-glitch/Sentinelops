
def analyze_resource(resource):
    findings = []

    if resource["type"] == "storage":
        if resource["public_access"]:
            findings.append({
                "resource": resource["name"],
                "severity": "HIGH",
                "finding": "Storage allows public access",
                "recommendation": "Disable public access unless explicitly required."
            })

        if not resource["encryption_enabled"]:
            findings.append({
                "resource": resource["name"],
                "severity": "HIGH",
                "finding": "Storage encryption is disabled",
                "recommendation": "Enable encryption for stored data."
            })

        if not resource["logging_enabled"]:
            findings.append({
                "resource": resource["name"],
                "severity": "MEDIUM",
                "finding": "Storage logging is disabled",
                "recommendation": "Enable logging to support monitoring and investigations."
            })

    if resource["type"] == "firewall":
        if resource["unrestricted_inbound"]:
            findings.append({
                "resource": resource["name"],
                "severity": "HIGH",
                "finding": "Firewall allows unrestricted inbound traffic",
                "recommendation": "Restrict inbound traffic to approved ports and sources."
            })

    return findings
