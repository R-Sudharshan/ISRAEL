from detection.dns import detect_dns_tunneling
from detection.ssh import detect_ssh_abuse
# Beaconing usually requires state/multiple logs, so it might be triggered differently 
# or via a periodic job. For single-log processing, we include stateless checks.

def run_detection_pipeline(log_entry):
    """
    Runs all applicable stateless detection rules on a single normalized log entry.
    """
    alerts_found = []

    # 1. DNS Detection
    if log_entry.get('protocol') == 'dns' and log_entry.get('dns_qname'):
        dns_alert = detect_dns_tunneling(log_entry['dns_qname'])
        if dns_alert:
            alerts_found.append(dns_alert)

    # 2. SSH Detection
    if log_entry.get('protocol') == 'ssh':
        ssh_alert = detect_ssh_abuse(log_entry)
        if ssh_alert:
            alerts_found.append(ssh_alert)

    return alerts_found

def format_alert_object(detection_result, log_entry, log_id):
    """
    Standardizes the output alert object for the database.
    """
    return {
        "severity": detection_result['severity'],
        "detection_type": detection_result['type'],
        "src_ip": log_entry.get('src_ip', 'unknown'),
        "device": log_entry.get('device_type') or log_entry.get('src_ip'),
        "timestamp": log_entry.get('timestamp'),
        "raw_log_reference": log_id,
        "details": str(detection_result.get('indicators', ''))
    }
