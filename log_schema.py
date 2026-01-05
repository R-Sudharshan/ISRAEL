from datetime import datetime
from typing import Dict, Any, List, Optional
import ipaddress

class LogSchemaValidationException(Exception):
    pass

class LogSchema:
    def __init__(self, name: str, fields: Dict[str, Any], dependency_rules: List[Any] = None):
        self.name = name
        self.fields = fields # Field name -> type (str, int, 'ip', 'timestamp', etc.)
        self.dependency_rules = dependency_rules or []

    def validate(self, entry: Dict[str, Any]) -> bool:
        # 1. Check for unknown fields
        for key in entry.keys():
            if key not in self.fields:
                raise LogSchemaValidationException(f"Unknown field '{key}' in schema '{self.name}'")

        # 2. Check types and required fields (if not optional)
        # For simplicity, we assume fields in self.fields are allowed. 
        # We need a way to mark optional vs required.
        # Let's assume all defined fields are optional unless dependency rules force them, 
        # BUT they must match type if present.
        for key, expected_type in self.fields.items():
            if key in entry:
                if entry[key] is None:
                    continue # Null allowed if not strictly forbidden by logic
                
                value = entry[key]
                if not self._check_type(value, expected_type):
                     raise LogSchemaValidationException(f"Field '{key}' has invalid type. Expected {expected_type}, got {type(value)}")

        # 3. Check dependencies
        for rule in self.dependency_rules:
            rule.validate(entry)
            
        return True

    def _check_type(self, value: Any, expected_type: Any) -> bool:
        if expected_type == 'ip':
            # Check if valid IP string
            try:
                ipaddress.ip_address(value)
                return True
            except ValueError:
                return False
        elif expected_type == 'timestamp':
             return isinstance(value, datetime)
        elif expected_type == 'int':
            return isinstance(value, int)
        elif expected_type == 'str':
            return isinstance(value, str)
        elif isinstance(expected_type, list): # Enum
            return value in expected_type
        return True


class DependencyRule:
    def validate(self, entry: Dict[str, Any]):
        raise NotImplementedError

class IfThenRule(DependencyRule):
    def __init__(self, condition_field: str, condition_values: List[Any], then_required: List[str]):
        self.condition_field = condition_field
        self.condition_values = condition_values
        self.then_required = then_required

    def validate(self, entry: Dict[str, Any]):
        val = entry.get(self.condition_field)
        if val in self.condition_values:
            for req in self.then_required:
                if req not in entry or entry[req] is None:
                    raise LogSchemaValidationException(f"Rule Violation: If {self.condition_field} is {val}, then {req} is required.")

class IfThenNotRule(DependencyRule):
    def __init__(self, condition_field: str, condition_values: List[Any], then_forbidden: List[str]):
        self.condition_field = condition_field
        self.condition_values = condition_values
        self.then_forbidden = then_forbidden

    def validate(self, entry: Dict[str, Any]):
        val = entry.get(self.condition_field)
        if val in self.condition_values:
            for forb in self.then_forbidden:
                if forb in entry and entry[forb] is not None:
                     raise LogSchemaValidationException(f"Rule Violation: If {self.condition_field} is {val}, then {forb} must be null.")

# --- Schema Definitions ---

# Common Fields:
# timestamp, devname, devid, logid, type, subtype, level, vd, etc.

FIREWALL_SCHEMA = LogSchema(
    name="FirewallTraffic",
    fields={
        "timestamp": "timestamp",
        "date": "str", "time": "str", 
        "devname": "str", "devid": "str", "logid": "str", 
        "type": ["traffic"], "subtype": ["forward", "local"], 
        "level": ["notice", "warning", "alert"], "vd": "str",
        "srcip": "ip", "srcport": "int",
        "dstip": "ip", "dstport": "int",
        "proto": "int", 
        "service": "str",
        "action": ["accept", "deny", "close"],
        "policyid": "int",
        "sentbyte": "int", "rcvdbyte": "int",
        "duration": "int",
        "user": "str", "authuser": "str",
        "device_type": "str", "osname": "str",
        "app": "str", "appcat": "str",
        "sessionid": "int",
        "msg": "str"
    },
    dependency_rules=[
        # IF protocol is TCP(6) or UDP(17), ports required
        IfThenRule("proto", [6, 17], ["srcport", "dstport"]),
        # IF action is accept, policyid required
        IfThenRule("action", ["accept"], ["policyid"]),
        # IF action is deny, usually minimal bytes
        # IF sessionid exists, action is usually accept or close
    ]
)

WEB_ACCESS_SCHEMA = LogSchema(
    name="WebAccess",
    fields={
        "timestamp": "timestamp",
        "date": "str", "time": "str",
        "devname": "str", "devid": "str", "type": ["utm"], "subtype": ["webfilter"],
        "srcip": "ip", "dstip": "ip", 
        "user": "str", "group": "str",
        "url": "str", "hostname": "str",
        "action": ["allow", "block", "monitor"],
        "cat": "int", "catdesc": "str", # Category
        "msg": "str",
        "service": ["HTTP", "HTTPS"],
        "profile": "str"
    },
    dependency_rules=[
        IfThenRule("action", ["block"], ["msg"])
    ]
)

IOT_SCHEMA = LogSchema(
    name="IoTDevice",
    fields={
        "timestamp": "timestamp",
        "date": "str", "time": "str",
        "devname": "str", "devid": "str", "type": ["event"], "subtype": ["system"],
        "srcip": "ip", 
        "device_id": "str",
        "firmware": "str",
        "status": ["online", "offline", "error", "update"],
        "cpu_load": "int", 
        "mem_usage": "int",
        "msg": "str"
    },
    dependency_rules=[]
)

def validate_entry(entry: Dict[str, Any], schema: LogSchema):
    return schema.validate(entry)
