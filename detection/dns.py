import math
from collections import Counter

def calculate_entropy(string):
    """Calculates the Shannon entropy of a string."""
    if not string:
        return 0
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

def detect_dns_tunneling(domain, config=None):
    """
    Analyzes a domain string for signs of DNS tunneling.
    Returns a dictionary with detection details if suspicious, else None.
    """
    if config is None:
        config = {"entropy_threshold": 4.5, "max_length": 50}
    
    if not domain:
        return None

    # Tunable thresholds from config
    MAX_LENGTH = config.get("max_length", 50) 
    HIGH_ENTROPY_THRESHOLD = config.get("entropy_threshold", 4.5) 

    details = []
    
    # Check 1: Query Length
    # focusing on the subdomain part (stripping TLD/SLD if simple, or just raw length)
    # For a simple check, raw length of the full query or the largest label is good.
    if len(domain) > MAX_LENGTH:
        details.append(f"High query length ({len(domain)})")

    # Check 2: Entropy
    entropy = calculate_entropy(domain)
    if entropy > HIGH_ENTROPY_THRESHOLD:
        details.append(f"High entropy ({entropy:.2f})")

    if details:
        return {
            "type": "DNS Tunneling",
            "severity": "High",
            "indicators": details,
            "domain": domain,
            "mitre_tactic": "Command and Control (TA0011)",
            "mitre_technique": "Application Layer Protocol: DNS (T1071.004)"
        }
    
    return None

def analyze_subdomain_volume(logs, threshold=None):
    """
    Checks for excessive unique subdomains for a common parent domain in a batch of logs.
    Expects 'logs' to be a list of dicts with 'dns_qname' or similar field.
    """
    if threshold is None:
        # Try to load from default if not provided
        threshold = 10
    # This is a stateful batch check
    domain_counts = Counter()
    parent_domains = {}

    alerts = []

    for log in logs:
        domain = log.get('dns_qname') # Assuming normalized field name
        if not domain:
            continue
        
        parts = domain.split('.')
        if len(parts) > 2:
            parent = ".".join(parts[-2:])
            if parent not in parent_domains:
                parent_domains[parent] = set()
            parent_domains[parent].add(domain)

    for parent, subdomains in parent_domains.items():
        if len(subdomains) > threshold:
             alerts.append({
                "type": "Excessive Unique Subdomains",
                "severity": "Medium",
                "domain": parent,
                "count": len(subdomains),
                "mitre_tactic": "Command and Control (TA0011)",
                "mitre_technique": "Application Layer Protocol: DNS (T1071.004)"
            })
            
    return alerts
