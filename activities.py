from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import random
import ipaddress

from entities import Entity, User, Device, NetworkSession, Attacker
from log_schema import FIREWALL_SCHEMA, WEB_ACCESS_SCHEMA, IOT_SCHEMA

class Activity:
    """
    Base class for all simulated activities.
    An activity represents a real-world action (e.g. "User browse web", "Hacker scans port").
    It emits one or more log entries.
    """
    def __init__(self, start_time: datetime):
        self.start_time = start_time
        
    def generate_logs(self) -> List[Dict[str, Any]]:
        """
        Returns a list of raw log dictionaries. 
        These will be validated against schemas by the SimulationEngine.
        """
        raise NotImplementedError

class NormalWebRequest(Activity):
    def __init__(self, start_time: datetime, user: User, src_device: Device, dest_ip: str, url: str):
        super().__init__(start_time)
        self.user = user
        self.src_device = src_device
        self.dest_ip = dest_ip
        self.url = url
        
    def generate_logs(self) -> List[Dict[str, Any]]:
        logs = []
        
        # 1. Firewall Traffic Log (Allow)
        fw_log = {
            "timestamp": self.start_time,
            "devname": "FGT-Core", "devid": "FGT60F12345", "logid": "0000000013",
            "type": "traffic", "subtype": "forward", "level": "notice", "vd": "root",
            "srcip": self.src_device.ip_address, "srcport": random.randint(10000, 60000),
            "dstip": self.dest_ip, "dstport": 443,
            "proto": 6, 
            "service": "HTTPS",
            "action": "accept",
            "policyid": 101,
            "sentbyte": random.randint(500, 2000),
            "rcvdbyte": random.randint(2000, 10000),
            "duration": random.randint(1, 10),
            "user": self.user.username,
            "device_type": self.src_device.type,
            "appcat": "web",
            "msg": "Allowed HTTPS traffic"
        }
        logs.append(fw_log)
        
        # 2. Web Access Log
        web_log = {
            "timestamp": self.start_time,
            "devname": "FGT-Core", "devid": "FGT60F12345", "type": "utm", "subtype": "webfilter",
            "srcip": self.src_device.ip_address,
            "dstip": self.dest_ip,
            "user": self.user.username,
            "url": self.url,
            "hostname": self.url.split('/')[0],
            "action": "allow",
            "cat": 52, "catdesc": "Information Technology",
            "service": "HTTPS",
            "msg": "URL belongs to an allowed category in the policy"
        }
        logs.append(web_log)
        
        return logs

class IoTHeartbeat(Activity):
    def __init__(self, start_time: datetime, device: Device, dest_ip: str):
        super().__init__(start_time)
        self.device = device
        self.dest_ip = dest_ip
        
    def generate_logs(self) -> List[Dict[str, Any]]:
        logs = []
        # Firewall Log only
        fw_log = {
            "timestamp": self.start_time,
            "devname": "FGT-IoT-Edge", "devid": "FGT60F55555", "logid": "0000000013",
            "type": "traffic", "subtype": "forward", "level": "notice", "vd": "iot-vrf",
            "srcip": self.device.ip_address, "srcport": random.randint(30000, 40000),
            "dstip": self.dest_ip, "dstport": 8883, # MQTT over SSL
            "proto": 6,
            "service": "MQTT",
            "action": "accept",
            "policyid": 55,
            "sentbyte": 150, "rcvdbyte": 150,
            "duration": 0,
            "device_type": "iot-sensor",
            "msg": "IoT Verify"
        }
        logs.append(fw_log)
        return logs

class SSHBruteForce(Activity):
    def __init__(self, start_time: datetime, attacker: Attacker, target_ip: str):
        super().__init__(start_time)
        self.attacker = attacker
        self.target_ip = target_ip
        self.attempts = 10 # Number of fast attempts
        
    def generate_logs(self) -> List[Dict[str, Any]]:
        logs = []
        base_time = self.start_time
        
        for i in range(self.attempts):
            t = base_time + timedelta(seconds=i*0.5)
            # 9 failures then maybe 1 success? Or just all failures.
            # Let's say all failures for this activity usually.
            
            fw_log = {
                "timestamp": t,
                "devname": "FGT-Core", "devid": "FGT60F12345", "logid": "0000000013",
                "type": "traffic", "subtype": "local", "level": "warning",
                "srcip": self.attacker.ip_address, "srcport": random.randint(40000, 60000),
                "dstip": self.target_ip, "dstport": 22,
                "proto": 6, "service": "SSH",
                "action": "deny", # Brute force often gets denied by IPS or Policy eventually, or 'accept' but login fails (which is an app log, but here we simulate network level noise)
                # But wait, SSH Login Failures are often Application logs on the server.
                # Use logic from user prompt: "action=deny → policy_id MUST exist" dependency.
                # Let's say action=deny (Firewall block) or action=accept (Firewall allows, but server rejects - we don't have server logs yet, only network).
                # Let's allow it but maybe trigger an IPS signature in a real scenario. 
                # For basic schema:
                "policyid": 4,
                "sentbyte": 0, "rcvdbyte": 0,
                "duration": 0,
                "msg": "Implicit Deny: Policy Violation",
                "_label": "malicious", # Gound truth
                "_attack_type": "ssh_bruteforce"
            }
            logs.append(fw_log)
            
        return logs

class MaliciousFileUpload(Activity):
    def __init__(self, start_time: datetime, attacker: Attacker, target_ip: str, filename: str):
         super().__init__(start_time)
         self.attacker = attacker
         self.target_ip = target_ip
         self.filename = filename

    def generate_logs(self) -> List[Dict[str, Any]]:
        logs = []
        
        # 1. Initial Access Request (POST)
        logs.append({
            "timestamp": self.start_time,
            "devname": "FGT-Core", "devid": "FGT60F12345", "type": "utm", "subtype": "webfilter",
            "srcip": self.attacker.ip_address,
            "dstip": self.target_ip,
            "user": "N/A",
            "url": f"/upload.php?file={self.filename}",
            "hostname": "internal-web",
            "action": "block", # Stopped by WAF usually
            "cat": 0, "catdesc": "Uncategorized",
            "service": "HTTP",
            "msg": "WAF Blocked Malicious Upload",
            "_label": "malicious",
            "_attack_type": "file_upload_exploit"
        })
        
        return logs

class DNSExfiltration(Activity):
    def __init__(self, start_time: datetime, infected_device: Device, c2_server: str):
        super().__init__(start_time)
        self.device = infected_device
        self.c2_server = c2_server
        
    def generate_logs(self) -> List[Dict[str, Any]]:
        logs = []
        # Generate a burst of DNS queries
        for i in range(5):
             t = self.start_time + timedelta(seconds=i*0.2)
             encoded_data = "".join(random.choices("abcdef0123456789", k=32))
             fqdn = f"{encoded_data}.malicious-c2.com"
             
             logs.append({
                "timestamp": t,
                "devname": "FGT-Core", "devid": "FGT60F12345", "logid": "0000000013",
                "type": "traffic", "subtype": "forward", "level": "notice",
                "srcip": self.device.ip_address, "srcport": random.randint(50000, 60000),
                "dstip": "8.8.8.8", "dstport": 53,
                "proto": 17, "service": "DNS",
                "action": "accept",
                "policyid": 1,
                "sentbyte": 100, "rcvdbyte": 200,
                "duration": 0,
                "appcat": "network-service",
                "_label": "malicious",
                "_attack_type": "dns_tunneling"
             })
        return logs
