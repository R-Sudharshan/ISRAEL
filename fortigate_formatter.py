import csv
import json
import logging
from datetime import datetime
from typing import Dict, Any, List

class FortiLogBuilder:
    """
    Handles the construction and formatting of FortiGate-style logs.
    """

    def __init__(self):
        self.default_fields = {
            "devname": "FGT-60F",
            "devid": "FGT60F1234567890",
            "logid": "0000000013",
            "type": "traffic",
            "subtype": "forward",
            "level": "notice",
            "vd": "root",
            "appcat": "unscanned"
        }

    def build_log_entry(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merges provided data with default fields and ensures correct types.
        """
        entry = self.default_fields.copy()
        entry.update(data)
        
        # Ensure timestamp fields exist
        if "timestamp" in entry:
            dt = entry["timestamp"]
            entry["date"] = dt.strftime("%Y-%m-%d")
            entry["time"] = dt.strftime("%H:%M:%S")
            # Remove raw timestamp object from final dict if we want strict FGT fields, 
            # but keeping it might be useful for sorting before write.
            # We will remove it in the formatting step.
            
        return entry

    def format_kv_string(self, entry: Dict[str, Any]) -> str:
        """
        Converts a dictionary to a FortiGate key=value string.
        """
        # defined order for common fields to look realistic
        field_order = [
            "date", "time", "devname", "devid", "logid", "type", "subtype", 
            "level", "vd", "srcip", "srcport", "dstip", "dstport", "proto", 
            "service", "action", "policyid", "sentbyte", "rcvdbyte", 
            "duration", "user", "authuser", "device_type"
        ]
        
        parts = []
        
        # Add ordered fields first
        for key in field_order:
            if key in entry:
                value = entry[key]
                # Wrap value in quotes if it contains spaces, though FGT doesn't always do this.
                # Standard FGT practice: values with spaces are quoted.
                str_val = str(value)
                if ' ' in str_val:
                    str_val = f'"{str_val}"'
                parts.append(f"{key}={str_val}")
        
        # Add remaining fields
        for key, value in entry.items():
            if key not in field_order and key != "timestamp":
                str_val = str(value)
                if ' ' in str_val:
                    str_val = f'"{str_val}"'
                parts.append(f"{key}={str_val}")
                
        return " ".join(parts)

class LogWriter:
    """
    Writes logs to Files (CSV/JSON).
    """
    def __init__(self, output_base_name: str):
        self.csv_file = f"{output_base_name}.csv"
        # self.json_file = f"{output_base_name}.json" # Requirement: Output in CSV and JSON
        self.kv_file = f"{output_base_name}.log" # Traditional FGT raw format

    def write_csv(self, logs: List[Dict[str, Any]]):
        if not logs:
            return
            
        # Extract headers from the superset of keys
        headers = set()
        for log in logs:
            headers.update(log.keys())
        
        # Remove internal keys
        if "timestamp" in headers:
            headers.remove("timestamp")
            
        sorted_headers = sorted(list(headers))
        
        # Ensure standard fields are first
        priority = ["date", "time", "devname", "devid", "srcip", "srcport", "dstip", "dstport"]
        final_headers = []
        for p in priority:
            if p in headers:
                final_headers.append(p)
                sorted_headers.remove(p)
        final_headers.extend(sorted_headers)

        with open(self.csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=final_headers)
            writer.writeheader()
            for log in logs:
                row = log.copy()
                if "timestamp" in row:
                    del row["timestamp"]
                writer.writerow(row)
                
        print(f"[-] CSV logs written to {self.csv_file}")

    def write_json(self, logs: List[Dict[str, Any]], output_name: str):
        safe_logs = []
        for log in logs:
             entry = log.copy()
             if "timestamp" in entry:
                 entry["timestamp_iso"] = entry["timestamp"].isoformat()
                 del entry["timestamp"]
             safe_logs.append(entry)
             
        filename = f"{output_name}.json"
        with open(filename, 'w') as f:
            json.dump(safe_logs, f, indent=2)
            
        print(f"[-] JSON logs written to {filename}")

    def write_raw(self, logs: List[Dict[str, Any]], formatter: FortiLogBuilder):
        with open(self.kv_file, 'w') as f:
            for log in logs:
                line = formatter.format_kv_string(log)
                f.write(line + "\n")
        print(f"[-] Raw FortiGate logs written to {self.kv_file}")
