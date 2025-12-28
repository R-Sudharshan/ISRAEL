import json
import random
import argparse
import sys
from datetime import datetime, timedelta
import ipaddress
from typing import List, Dict, Any

from fortigate_formatter import FortiLogBuilder, LogWriter
from attack_profiles import AttackSimulator

class TrafficGenerator:
    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
            
        self.formatter = FortiLogBuilder()
        self.writer = LogWriter("simulated_fortigate_logs")
        self.attacker = AttackSimulator(self.config)
        
        # Cache network objects
        self.internal_nets = [ipaddress.IPv4Network(cidr) for cidr in self.config["network"]["internal_cidrs"]]
        self.external_nets = [ipaddress.IPv4Network(cidr) for cidr in self.config["network"]["external_cidrs"]]

    def _get_random_internal_ip(self) -> str:
        subnet = random.choice(self.internal_nets)
        network_int = int(subnet.network_address)
        max_hosts = subnet.num_addresses - 1
        return str(ipaddress.IPv4Address(network_int + random.randint(1, max_hosts)))

    def _get_random_external_ip(self) -> str:
        subnet = random.choice(self.external_nets)
        network_int = int(subnet.network_address)
        max_hosts = subnet.num_addresses - 1
        return str(ipaddress.IPv4Address(network_int + random.randint(1, max_hosts)))
        
    def generate_baseline(self, start_time: datetime, duration_hours: int) -> List[Dict[str, Any]]:
        print("[-] Generating baseline traffic...")
        logs = []
        end_time = start_time + timedelta(hours=duration_hours)
        current_time = start_time
        
        # Pre-calculate services weights
        services = self.config["baseline"]["services"]
        service_choices = [s for s in services]
        service_weights = [s["weight"] for s in services]
        
        # Simulation loop
        # Instead of second-by-second, we'll jump by small random intervals
        while current_time < end_time:
            # Time increment: Random between 0.1s and 2s for "busty" feel
            dt = random.uniform(0.1, 2.0)
            current_time += timedelta(seconds=dt)
            
            if current_time > end_time:
                break
                
            # Randomly decide how many events in this burst (1 to 5)
            burst_size = random.randint(1, 5)
            
            for _ in range(burst_size):
                svc = random.choices(service_choices, weights=service_weights, k=1)[0]
                
                src_ip = self._get_random_internal_ip()
                dst_ip = self._get_random_external_ip()
                
                # NAT/Port logic simulated loosely
                src_port = random.randint(10000, 65000)
                
                # Protocol
                proto = svc["proto"]
                dst_port = svc["port"]
                
                # Bytes
                sent = random.randint(100, 5000)
                rcvd = random.randint(100, 50000)
                
                log = {
                    "timestamp": current_time,
                    "srcip": src_ip,
                    "dstip": dst_ip,
                    "srcport": src_port,
                    "dstport": dst_port,
                    "proto": proto,
                    "service": svc["name"],
                    "action": "accept",
                    "policyid": 1,
                    "sentbyte": sent,
                    "rcvdbyte": rcvd,
                    "duration": random.randint(1, 60),
                    "user": f"user-{random.randint(1, 50)}",
                    "device_type": "workstation",
                    "level": "notice",
                    "logid": "0000000013",
                    "srccountry": "Reserved",
                    "dstcountry": "United States"
                }
                logs.append(log)
                
        print(f"[-] Generated {len(logs)} baseline events.")
        return logs

    def run(self):
        # Setup time
        # Use fixed start time for determinism if needed, or now
        # Config says start_time_offset_hours
        now = datetime.now()
        start_offset = self.config["simulation"].get("start_time_offset_hours", 0)
        start_time = now - timedelta(hours=start_offset)
        duration = self.config["simulation"]["duration_hours"]
        
        # 1. Generate Baseline
        all_logs = self.generate_baseline(start_time, duration)
        
        # 2. Generate Attacks
        print("[-] Injecting attacks...")
        
        # IoT Bruteforce
        iot_logs = self.attacker.generate_iot_bruteforce(start_time, duration)
        print(f"    - Injected {len(iot_logs)} IoT bruteforce events")
        all_logs.extend(iot_logs)
        
        # DNS Tunneling
        dns_logs = self.attacker.generate_dns_tunneling(start_time, duration)
        print(f"    - Injected {len(dns_logs)} DNS tunneling events")
        all_logs.extend(dns_logs)
        
        # Beaconing
        beacon_logs = self.attacker.generate_beaconing(start_time, duration)
        print(f"    - Injected {len(beacon_logs)} Beaconing events")
        all_logs.extend(beacon_logs)
        
        # 3. Sort by timestamp
        print("[-] Sorting logs by timestamp...")
        all_logs.sort(key=lambda x: x["timestamp"])
        
        # 4. Final Formatting & Write
        # Using build_log_entry to ensure defaults
        final_logs = [self.formatter.build_log_entry(log) for log in all_logs]
        
        print("[-] Writing output...")
        self.writer.write_csv(final_logs)
        self.writer.write_json(final_logs, "simulated_fortigate_logs")
        self.writer.write_raw(final_logs, self.formatter)
        print("[+] Simulation complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synthetic FortiGate Log Generator")
    parser.add_argument("--config", default="config.json", help="Path to config file")
    args = parser.parse_args()
    
    gen = TrafficGenerator(args.config)
    gen.run()
