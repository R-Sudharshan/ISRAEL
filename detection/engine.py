from detection.dns import detect_dns_tunneling
from detection.ssh import detect_ssh_abuse
# Beaconing usually requires state/multiple logs, so it might be triggered differently 
# or via a periodic job. For single-log processing, we include stateless checks.
import json
import os

def load_detection_config():
    config_path = os.path.join(os.path.dirname(__file__), '..', 'config.json')
    try:
        with open(config_path, 'r') as f:
            return json.load(f).get('detection_rules', {})
    except:
        return {}

def run_detection_pipeline(log_entry):
    """
    Runs all applicable stateless detection rules on a single normalized log entry.
    """
    alerts_found = []

    # Load live config
    config = load_detection_config()

    # 1. DNS Detection
    if log_entry.get('protocol') == 'dns' and log_entry.get('dns_qname'):
        dns_alert = detect_dns_tunneling(log_entry['dns_qname'], config.get('dns', {}))
        if dns_alert:
            alerts_found.append(dns_alert)

    # 2. SSH Detection
    if log_entry.get('protocol') == 'ssh':
        ssh_alert = detect_ssh_abuse(log_entry, config.get('ssh', {}))
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
        "details": str(detection_result.get('indicators', '')),
        "mitre_tactic": detection_result.get('mitre_tactic'),
        "mitre_technique": detection_result.get('mitre_technique')
    }
