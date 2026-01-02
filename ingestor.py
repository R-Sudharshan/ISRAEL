import json
from dateutil import parser
from datetime import datetime

class LogIngestor:
    def __init__(self):
        pass

    def parse_log_file(self, file_path):
        """
        Reads a JSON log file and returns a list of normalized log dictionaries.
        """
        normalized_logs = []
        try:
            with open(file_path, 'r') as f:
                # Assuming file contains one JSON object per line (JSONL) or a JSON array
                content = f.read().strip()
                if content.startswith('['):
                     raw_logs = json.loads(content)
                else: 
                     # Handle JSONL
                     raw_logs = [json.loads(line) for line in content.splitlines() if line.strip()]

            for raw in raw_logs:
                normalized = self.normalize_log(raw)
                if normalized:
                    normalized_logs.append(normalized)
                    
            return normalized_logs

        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
            return []
        except Exception as e:
            print(f"Error reading file: {e}")
            return []

    def normalize_log(self, raw_log):
        """
        Maps raw log fields to the standard internal schema.
        Standard Schema: timestamp, src_ip, dst_ip, device_type, protocol, action, dns_qname
        """
        try:
            # Flexible parsing capable of handling typical Fortigate/Generic JSON structure
            
            # Timestamp parsing
            ts_str = raw_log.get('timestamp') or raw_log.get('date') + " " + raw_log.get('time', '00:00:00')
            try:
                timestamp = parser.parse(ts_str)
            except:
                timestamp = datetime.now()

            return {
                "timestamp": timestamp,
                "src_ip": raw_log.get('srcip', '0.0.0.0'),
                "dst_ip": raw_log.get('dstip', '0.0.0.0'),
                "device_type": raw_log.get('device_type') or raw_log.get('devid', 'unknown'),
                "protocol": (raw_log.get('service') or raw_log.get('proto') or 'unknown').lower(),
                "action": raw_log.get('action', 'unknown'),
                "dns_qname": raw_log.get('qname'), # specialized field for DNS logs
                "raw_log": json.dumps(raw_log)
            }
        except Exception as e:
            # print(f"Normalization failed for log: {e}") 
            return None
