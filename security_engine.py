def clean_alert(raw_alert: dict) -> dict:
    """
    Cleans and standardizes raw alert data.
    Ensures that essential fields exist and provides default values if missing.
    """
    return {
        "ip": raw_alert.get("ip", "Unknown"),
        "risk": raw_alert.get("risk", "Unknown"),
        "desc": raw_alert.get("desc", "No description provided"),
    }


def get_action(risk_level: str) -> str:
    """
    Maps the risk severity to an operation action.
    Returns the required security measure based on the risk level.
    """
    if risk_level == "Critical":
        return "BLOCK IP"
    elif risk_level == "High":
        return "INVESTIGATE"
    else:
        return "MONITOR"


def process_alters(alters: list):
    """
    Main pipeline function.
    Iterates through the list of raw alters and processes each one sequentially.
    """
    print("--- Starting Threat Processing Pipeline ---")

    for item in alters:
        # 1. Clean the data
        # 'clean_alert' takes the raw dictionary and returns a standardized one
        clean_data = clean_alert(item)

        # 2. Determine the security action
        #'get_action' takes the risk level and returns an action command
        action = get_action(clean_data["risk"])

        # 3.Log the result to the console
        print(f"IP:{clean_data['ip']} | Risk: {clean_data['risk']} | Action: {action}")

    print("--- Processing Complete ---")


# The entry point:
if __name__ == "__main__":
    # Mock data representing incoming security events
    raw_data = [
        {"ip": "1.1.1.1", "risk": "Critical", "desc": "Unauthorized SSH Access"},
        {
            "ip": "192.168.10.120",
            "risk": "High",
            "desc": "Multiple Failed Login Attempts",
        },
        {"ip": "10.0.0.50", "risk": "Medium", "desc": "Unusual Network Traffic"},
        {"ip": "172.16.0.1", "desc": "Unknown Activity"},  # testing default value"}
    ]

    # Execte the pipeline with the mock data
    process_alters(raw_data)
