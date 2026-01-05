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

            # Start with raw_log to keep all fields (e.g. log_type, auth_result, process_name)
            normalized = raw_log.copy()
            
            # Update with standardized fields if needed (converting srcip -> src_ip if standard name differs)
            # But our generator already uses src_ip. 
            # We just need to ensure timestamp is datetime object
            
            normalized['timestamp'] = timestamp
            
            # Map legacy keys if present (for real logs)
            if 'srcip' in raw_log and 'src_ip' not in raw_log: normalized['src_ip'] = raw_log['srcip']
            if 'dstip' in raw_log and 'dst_ip' not in raw_log: normalized['dst_ip'] = raw_log['dstip']
            if 'srcport' in raw_log and 'src_port' not in raw_log: normalized['src_port'] = raw_log['srcport']
            if 'dstport' in raw_log and 'dst_port' not in raw_log: normalized['dst_port'] = raw_log['dstport']
            
            # Ensure raw_log string is present
            if 'raw_log' not in normalized or not isinstance(normalized['raw_log'], str):
                 normalized['raw_log'] = json.dumps(raw_log, default=str)
                 
            return normalized
        except Exception as e:
            # print(f"Normalization failed for log: {e}") 
            return None
