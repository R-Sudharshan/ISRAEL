def detect_ssh_abuse(log_entry, config=None):
    """
    Analyzes a single log entry for SSH abuse from IoT devices.
    Returns a dictionary with detection details if suspicious, else None.
    """
    if config is None:
        config = {"check_iot_types": True, "fail_threshold_enabled": True}
    
    # IoT Device Types often targeted or used as jump hosts
    SUSPICIOUS_IOT_TYPES = ['camera', 'dvr', 'nvr', 'printer', 'router', 'thermostat']
    
    device_type = str(log_entry.get('device_type', '')).lower()
    protocol = str(log_entry.get('protocol', '')).lower()
    action = str(log_entry.get('action', '')).lower()
    
    if protocol not in ['ssh', '6', 'tcp']:
        return None

    detections = []

    # Check 1: SSH Traffic from known simple IoT devices
    if config.get("check_iot_types", True):
        for iot_type in SUSPICIOUS_IOT_TYPES:
            if iot_type in device_type:
                 detections.append(f"Unexpected SSH traffic from IoT device type: {device_type}")
                 break
    
    # Check 2: Failed Login Attempts
    if config.get("fail_threshold_enabled", True):
        if 'fail' in action or action == 'deny':
             detections.append("SSH Authentication Failure")

    if detections:
        # Determine severity
        severity = "Medium"
        if "Authentication Failure" in detections and len(detections) > 1:
            severity = "High" # IoT device failing auth is very suspicious
            
        return {
            "type": "SSH Abuse",
            "severity": severity,
            "indicators": detections,
            "src_ip": log_entry.get('src_ip'),
            "device_type": device_type,
            "mitre_tactic": "Credential Access (TA0006)",
            "mitre_technique": "Brute Force (T1110)"
        }

    return None
