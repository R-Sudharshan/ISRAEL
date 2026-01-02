import random
import ipaddress
import string
from datetime import datetime, timedelta
from typing import List, Dict, Any

class AttackSimulator:
    """
    Generates specific attack traffic patterns based on configuration.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.iot_config = config["attacks"]["iot_bruteforce"]
        self.dns_config = config["attacks"]["dns_tunneling"]
        self.beacon_config = config["attacks"]["beaconing"]
        
        self.external_cidrs = [ipaddress.IPv4Network(cidr) for cidr in config["network"]["external_cidrs"]]
        self.internal_cidrs = [ipaddress.IPv4Network(cidr) for cidr in config["network"]["internal_cidrs"]]

    def _get_random_external_ip(self) -> str:
        subnet = random.choice(self.external_cidrs)
        # Generate a random host within the subnet
        # random.choice is slow for large networks, simpler to verify logic
        # For /24 or /16, we can pick a random offset
        network_int = int(subnet.network_address)
        max_hosts = subnet.num_addresses - 1
        return str(ipaddress.IPv4Address(network_int + random.randint(1, max_hosts)))

    def _get_start_time(self, base_time: datetime, duration_hours: int) -> datetime:
        """Returns a random timestamp within the simulation window."""
        offset_seconds = random.randint(0, duration_hours * 3600)
        return base_time + timedelta(seconds=offset_seconds)

    def generate_iot_bruteforce(self, start_time: datetime, duration_hours: int) -> List[Dict[str, Any]]:
        if not self.iot_config["enabled"]:
            return []
            
        logs = []
        target_port = self.iot_config["target_port"]
        attempts = self.iot_config["attempts_per_run"]
        
        
        iot_count = self.config["devices"]["iot"]["count"]
        victim_idx = random.randint(1, iot_count)
        src_ip = f"192.168.1.{200 + victim_idx}"
        dev_name = f"{self.config['devices']['iot']['prefix']}{victim_idx}"
        
        
        dst_ip = self._get_random_external_ip()
        
       
        attack_start = self._get_start_time(start_time, duration_hours)
        
        for i in range(attempts):
            timestamp = attack_start + timedelta(milliseconds=i * random.randint(50, 200)) # Fast interval
            
   
            is_success = random.random() < self.iot_config["success_rate"]
            action = "accept" if is_success else "deny"
            
            
            log = {
                "timestamp": timestamp,
                "srcip": src_ip,
                "dstip": dst_ip,
                "srcport": random.randint(10000, 65000),
                "dstport": target_port,
                "proto": 6,
                "service": "SSH",
                "action": "accept", 
                "policyid": 101,
                "sentbyte": random.randint(100, 300), 
                "rcvdbyte": random.randint(100, 300),
                "duration": random.randint(1, 3),
                "user": "N/A",
                "device_type": "iot_camera",
                "level": "notice",
                "logid": "0000000013",
                "msg": "SSH connection established"
            }
            logs.append(log)
            
        return logs

    def generate_dns_tunneling(self, start_time: datetime, duration_hours: int) -> List[Dict[str, Any]]:
        if not self.dns_config["enabled"]:
            return []
            
        logs = []
        domain_suffix = self.dns_config["domain_suffix"]
        
    
        src_ip = "192.168.1.105" 
        dns_server = self.config["network"]["dns_servers"][0] # 8.8.8.8
        
   
        total_minutes = duration_hours * 60
        rate = self.dns_config["query_rate_per_minute"]
        total_queries = total_minutes * rate
        
        current_time = start_time
        
        for i in range(total_queries):
            current_time += timedelta(seconds=60/rate + random.uniform(-0.1, 0.1))
            
            subdomain_len = random.randint(30, 60) # Long subdomain
            subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=subdomain_len))
            fqdn = f"{subdomain}.{domain_suffix}"
            
            log = {
                "timestamp": current_time,
                "srcip": src_ip,
                "dstip": dns_server,
                "srcport": random.randint(10000, 65000),
                "dstport": 53,
                "proto": 17,
                "service": "DNS",
                "action": "accept",
                "policyid": 1,
                "sentbyte": random.randint(80, 150),
                "rcvdbyte": random.randint(200, 500),
                "duration": 0,
                "user": "bob.smith",
                "device_type": "Windows PC",
                "level": "notice",
                "logid": "0000000013",
                "qname": fqdn
            }
            logs.append(log)
            
        return logs

    def generate_beaconing(self, start_time: datetime, duration_hours: int) -> List[Dict[str, Any]]:
        if not self.beacon_config["enabled"]:
            return []
            
        logs = []
        c2_ip = self.beacon_config["target_ip"]
        interval = self.beacon_config["interval_seconds"]
        jitter = self.beacon_config["jitter_percent"]
        
        src_ip = "192.168.1.55"
        
        current_time = start_time
        end_time = start_time + timedelta(hours=duration_hours)
        
        while current_time < end_time:
            jitter_sec = interval * jitter
            actual_interval = interval + random.uniform(-jitter_sec, jitter_sec)
            current_time += timedelta(seconds=actual_interval)
            
            if current_time > end_time:
                break
                
            log = {
                "timestamp": current_time,
                "srcip": src_ip,
                "dstip": c2_ip,
                "srcport": random.randint(49152, 65535), 
                "dstport": 443,
                "proto": 6,
                "service": "HTTPS",
                "action": "accept",
                "policyid": 1,
                "sentbyte": 1200,
                "rcvdbyte": 4500,
                "duration": random.randint(1, 2),
                "user": "SYSTEM",
                "device_type": "srv-db-01",
                "level": "notice",
                "logid": "0000000013"
            }
            logs.append(log)
            
        return logs
