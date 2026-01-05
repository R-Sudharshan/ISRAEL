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

            print(f"[*] Parsed {len(raw_logs)} raw logs from JSON.")
            for raw in raw_logs:
                normalized = self.normalize_log(raw)
                if normalized:
                    normalized_logs.append(normalized)
                else:
                    print(f"[!] Normalization failed for a log.")
                    
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
            ts_str = raw_log.get('timestamp_iso') or raw_log.get('timestamp')
            if not ts_str:
                ts_str = f"{raw_log.get('date')} {raw_log.get('time')}"
            
            try:
                timestamp = parser.parse(ts_str)
            except:
                timestamp = datetime.now()

            return {
                "timestamp": timestamp,
                "src_ip": raw_log.get('srcip'),
                "dst_ip": raw_log.get('dstip'),
                "src_port": raw_log.get('srcport'),
                "dst_port": raw_log.get('dstport'),
                "protocol": raw_log.get('proto'),
                "service": raw_log.get('service'),
                "action": raw_log.get('action'),
                "policyid": raw_log.get('policyid'),
                "sentbyte": raw_log.get('sentbyte'),
                "rcvdbyte": raw_log.get('rcvdbyte'),
                "duration": raw_log.get('duration'),
                "user": raw_log.get('user'),
                "device_type": raw_log.get('device_type'),
                "level": raw_log.get('level'),
                "logid": raw_log.get('logid'),
                "qname": raw_log.get('qname'),
                "raw_log": json.dumps(raw_log)
            }
        except Exception as e:
            # print(f"Normalization failed for log: {e}") 
            return None
