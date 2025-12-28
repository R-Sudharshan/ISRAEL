def detect_ssh_abuse(log_entry):
    """
    Analyzes a single log entry for SSH abuse from IoT devices.
    Returns a dictionary with detection details if suspicious, else None.
    """
    
    # IoT Device Types often targeted or used as jump hosts
    # In a real scenario, this would check against an inventory `devices` table or a larger list.
    SUSPICIOUS_IOT_TYPES = ['camera', 'dvr', 'nvr', 'printer', 'router', 'thermostat']
    
    device_type = log_entry.get('device_type', '').lower()
    protocol = log_entry.get('protocol', '').lower()
    action = log_entry.get('action', '').lower()
    
    if protocol != 'ssh':
        return None

    detections = []

    # Check 1: SSH Traffic from known simple IoT devices (often shouldn't imply outbound SSH)
    # This assumes 'src_ip' is the local IoT device.
    for iot_type in SUSPICIOUS_IOT_TYPES:
        if iot_type in device_type:
             detections.append(f"Unexpected SSH traffic from IoT device type: {device_type}")
             break
    
    # Check 2: Failed Login Attempts (Simple stateless check on single log, or requiring state)
    # Fortigate logs often have action='login_failed' or similar.
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
            "device_type": device_type
        }

    return None
