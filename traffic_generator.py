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
                
                # Device Type Selection
                if hasattr(self, 'device_categories') and self.device_categories:
                    dev_type = random.choice(self.device_categories)
                else:
                    dev_type = "workstation"

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
                    "device_type": dev_type,
                    "level": "notice",
                    "logid": "0000000013",
                    "srccountry": "Reserved",
                    "dstcountry": "United States"
                }
                logs.append(log)
                
        print(f"[-] Generated {len(logs)} baseline events.")
        return logs

    def run(self, counts=None, device_categories=None):
        """
        Runs the simulation. 
        'counts' can be a dict specifying exactly how many of each to generate.
        'device_categories' is a list of allowed device types.
        """
        now = datetime.now()
        # We align the simulation to END at 'now'
        duration = self.config["simulation"]["duration_hours"]
        start_time = now - timedelta(hours=duration)
        
        all_logs = []
        
        if device_categories:
            self.device_categories = device_categories
        else:
            self.device_categories = []
            
        if counts:
            # GRANULAR MODE
            if counts.get('baseline', 0) > 0:
                # We reuse generate_baseline but limit it or modify it
                # For simplicity, we generate a small batch based on the requested count
                print(f"[-] Generating {counts['baseline']} baseline events...")
                services = self.config["baseline"]["services"]
                service_choices = [s for s in services]
                service_weights = [s["weight"] for s in services]
                
                for _ in range(counts['baseline']):
                    svc = random.choices(service_choices, weights=service_weights, k=1)[0]
                    dt = random.uniform(0, duration * 3600)
                    ts = start_time + timedelta(seconds=dt)
                    log = {
                        "timestamp": ts,
                        "srcip": self._get_random_internal_ip(),
                        "dstip": self._get_random_external_ip(),
                        "srcport": random.randint(10000, 65000),
                        "dstport": svc["port"],
                        "proto": svc["proto"],
                        "service": svc["name"],
                        "action": "accept",
                        "policyid": 1,
                        "sentbyte": random.randint(100, 5000),
                        "rcvdbyte": random.randint(100, 50000),
                        "duration": random.randint(1, 60),
                        "user": f"user-{random.randint(1, 50)}",
                        "device_type": random.choice(self.device_categories) if self.device_categories else "workstation",
                        "level": "notice",
                        "logid": "0000000013"
                    }
                    all_logs.append(log)

            if counts.get('ssh', 0) > 0:
                print(f"[-] Injecting {counts['ssh']} SSH events...")
                # Temporarily override config for the generator
                orig_ssh = self.config["attacks"]["iot_bruteforce"]["attempts_per_run"]
                self.config["attacks"]["iot_bruteforce"]["attempts_per_run"] = counts['ssh']
                all_logs.extend(self.attacker.generate_iot_bruteforce(start_time, duration))
                self.config["attacks"]["iot_bruteforce"]["attempts_per_run"] = orig_ssh

            if counts.get('dns', 0) > 0:
                print(f"[-] Injecting {counts['dns']} DNS events...")
                # We need to modify AttackSimulator or just generate here. 
                # For now, we take a fraction of the standard rate to match the requested count roughly
                dns_logs = self.attacker.generate_dns_tunneling(start_time, duration)
                if len(dns_logs) > counts['dns']:
                    all_logs.extend(dns_logs[:counts['dns']])
                else:
                    all_logs.extend(dns_logs)

            if counts.get('beacon', 0) > 0:
                print(f"[-] Injecting {counts['beacon']} Beaconing events...")
                beacon_logs = self.attacker.generate_beaconing(start_time, duration)
                if len(beacon_logs) > counts['beacon']:
                    all_logs.extend(beacon_logs[:counts['beacon']])
                else:
                    all_logs.extend(beacon_logs)
        else:
            # BULK MODE (Default)
            all_logs.extend(self.generate_baseline(start_time, duration))
            print("[-] Injecting attacks...")
            all_logs.extend(self.attacker.generate_iot_bruteforce(start_time, duration))
            all_logs.extend(self.attacker.generate_dns_tunneling(start_time, duration))
            all_logs.extend(self.attacker.generate_beaconing(start_time, duration))
        
        # 3. Sort by timestamp
        all_logs.sort(key=lambda x: x["timestamp"])
        
        # 4. Final Formatting & Write
        final_logs = [self.formatter.build_log_entry(log) for log in all_logs]
        
        print(f"[-] Total logs generated: {len(final_logs)}")
        self.writer.write_csv(final_logs)
        self.writer.write_json(final_logs, "simulated_fortigate_logs")
        self.writer.write_raw(final_logs, self.formatter)
        print("[+] Simulation complete.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synthetic FortiGate Log Generator")
    parser.add_argument("--config", default="config.json", help="Path to config file")
    parser.add_argument("--baseline", type=int, default=0, help="Number of baseline logs to generate")
    parser.add_argument("--ssh", type=int, default=0, help="Number of SSH attack logs to generate")
    parser.add_argument("--dns", type=int, default=0, help="Number of DNS attack logs to generate")
    parser.add_argument("--beacon", type=int, default=0, help="Number of Beacon logs to generate")
    parser.add_argument("--categories", nargs="+", help="List of device categories (e.g. Router Printer)")
    args = parser.parse_args()
    
    gen = TrafficGenerator(args.config)
    
    # If any specific counts are provided, use granular mode
    if args.baseline or args.ssh or args.dns or args.beacon:
        granular_counts = {
            "baseline": args.baseline,
            "ssh": args.ssh,
            "dns": args.dns,
            "beacon": args.beacon
        }
        gen.run(granular_counts, device_categories=args.categories)
    else:
        gen.run(device_categories=args.categories)
