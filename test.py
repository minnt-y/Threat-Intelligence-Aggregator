# DAY 2: Simulating threat intelligence data
# Using variables to store individual threat information

# Intel details as variables
intel_title = "Suspicious Brute Force Attempt"
source_ip = "192.168.1.100"
severity = "High"
attack_type = "SSH Brute Force"  # Added as per your request
target_system = "Web-Server"

# Output the intelligence information
print(f"Intel Title: {intel_title}")
print(f"Source IP: {source_ip}")
print(f"Severity: {severity}")
print(f"Attack Type: {attack_type}")
print(f"Target system: {target_system}")


# List of alerts processed from the network gateway
alerts = [
    {"ip": "1.1.1.1", "risk": "Critical", "desc": "Unauthorized SSH Access"},
    {"ip": "2.2.2.2", "risk": "Medium", "desc": "Port Scanning"},
    {"ip": "3.3.3.3", "risk": "Low", "desc": "Policy Violation"},
]

# Process alerts with defensive logic and categorization
for alert in alerts:

    # Use .get() to avoid KeyError if fields are missing
    current_ip = alert.get("ip", "Unknown")
    current_risk = alert.get("risk", "Info")
    current_desc = alert.get("desc", "No description")

    # [Priority 1] Critical alerts require immediate incident response
    if current_risk == "Critical":
        print(
            f"[Critical]ALERT: {current_desc} from IP {current_ip}. Initiating automated containment..."
        )

    # [Priority 2] Medium/High alerts are flagged for operational monitoring
    elif current_risk in ["High", "Medium"]:
        print(
            f"[INFO] Monitoring event: {current_desc} from {current_ip} (Level: {current_risk})"
        )

    # [Priority 3] Low priority alerts are suppressed to reduce noise
    else:
        print(f"[DEBUG] Suppressing low risk event: {current_ip}")
