
import os
import yaml
import random
import datetime
from typing import List, Dict, Any

class PatternManager:
    def __init__(self, patterns_dir="pattern"):
        self.patterns_dir = patterns_dir
        self.patterns = self._scan_patterns()

    def _scan_patterns(self) -> List[str]:
        """Returns a list of available pattern names (subdirectories)."""
        if not os.path.exists(self.patterns_dir):
            return []
        
        # Get subdirectories
        return [d for d in os.listdir(self.patterns_dir) 
                if os.path.isdir(os.path.join(self.patterns_dir, d)) 
                and not d.startswith('.') 
                and d not in ['db', 'owasp']]

    def get_available_patterns(self) -> List[str]:
        return sorted(self.patterns)

    def load_payloads(self, pattern_name: str) -> List[str]:
        """Extracts payloads from YAML files in the pattern directory."""
        dir_path = os.path.join(self.patterns_dir, pattern_name)
        payloads = []
        
        if not os.path.exists(dir_path):
            return []

        for f_name in os.listdir(dir_path):
            if f_name.endswith('.yaml') or f_name.endswith('.yml'):
                f_path = os.path.join(dir_path, f_name)
                try:
                    with open(f_path, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                        new_loads = self._extract_from_rule(data)
                        payloads.extend(new_loads)
                except Exception as e:
                    print(f"Error loading {f_path}: {e}")
                    
        return list(set(payloads)) # Dedup

    def _extract_from_rule(self, rule_yaml: Dict) -> List[str]:
        """Heuristic extraction of payloads from Sigma detection rules."""
        payloads = []
        try:
            if 'detection' in rule_yaml and 'selection' in rule_yaml['detection']:
                sel = rule_yaml['detection']['selection']
                # Iterate over keys like 'request_uri|contains'
                for k, v in sel.items():
                    if 'contains' in k:
                        if isinstance(v, list):
                            payloads.extend(v)
                        elif isinstance(v, str):
                            payloads.append(v)
                    # Also check for 'keywords'
                    if 'keywords' in k:
                        if isinstance(v, list):
                            payloads.extend(v)
        except:
            pass
        return payloads

    def generate_logs(self, pattern_name: str, count: int, start_time: datetime.datetime) -> List[Dict[str, Any]]:
        """Generates logs for the specified pattern."""
        payloads = self.load_payloads(pattern_name)
        if not payloads:
            # Fallback if no specific payload found
            payloads = [f"Generic {pattern_name} Signature"]
            
        logs = []
        for _ in range(count):
            payload = random.choice(payloads)
            ts = start_time + datetime.timedelta(seconds=random.uniform(0, 3600))
            
            # Determine Log Type based on pattern name
            log_type = "application"
            if "IOT" in pattern_name.upper():
                log_type = "network"
            elif "DOS" in pattern_name.upper():
                log_type = "network"
                
            # Basic Log Template
            log = {
                "timestamp": ts,
                "log_type": log_type,
                "src_ip": f"192.168.1.{random.randint(20, 200)}",
                "dst_ip": f"10.0.0.{random.randint(10, 50)}",
                "user": "N/A",
                "http_method": "GET",
                "url": f"/search?q={payload}", # Inject payload into URL for visibility
                "status_code": 200,
                "user_agent": "Mozilla/5.0",
                "msg": f"Detected {pattern_name}: {payload}",
                "level": "warning",
                "action": "alert"
            }
            
            # Adjust for IOT
            if log_type == "network":
                log["src_port"] = random.randint(1024, 65535)
                log["dst_port"] = 80
                log["proto"] = "TCP"
            
            # Additional fields to satisfy schema if needed
            log["raw_log"] = f"Pattern Detection: {pattern_name} - {payload}"
            
            logs.append(log)
            
        return logs

if __name__ == "__main__":
    pm = PatternManager()
    print("Patterns:", pm.get_available_patterns())
    if pm.patterns:
        print("Payloads for first pattern:", pm.load_payloads(pm.patterns[0]))
