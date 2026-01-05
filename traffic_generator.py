import json
import random
import argparse
import sys
from datetime import datetime, timedelta
import ipaddress
from typing import List, Dict, Any

from fortigate_formatter import FortiLogBuilder, LogWriter
from attack_profiles import AttackSimulator
from dataset_loader import DatasetLoader

class TrafficGenerator:
    def _generate_single_log(self, svc, start_time, duration):
        dt = random.uniform(0, duration * 3600)
        ts = start_time + timedelta(seconds=dt)
        src_ip = self._get_random_internal_ip()
        dst_ip = self._get_random_external_ip() # Default to external unless overridden
        
        # Override for DNS if needed
        if svc['name'] == 'DNS':
            dst_ip = "8.8.8.8"

        log = {
            "timestamp": ts,
            "srcip": src_ip,
            "dstip": dst_ip,
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
            "device_type": "workstation",
            "level": "notice",
            "logid": "0000000013",
            "srccountry": "Reserved",
            "dstcountry": "United States",
            "agent": random.choice(self.user_agents) if "http" in svc['name'] else "N/A"
        }
        return log

    def __init__(self, config_path: str):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
            
        self.formatter = FortiLogBuilder()
        self.writer = LogWriter("simulated_fortigate_logs")
        self.attacker = AttackSimulator(self.config)
        
        # Dataset Integration
        self.use_dataset = self.config.get("dataset", {}).get("enabled", False)
        if self.use_dataset:
            self.loader = DatasetLoader(self.config["dataset"]["path"])
        
        # Cache network objects
        self.internal_nets = [ipaddress.IPv4Network(cidr) for cidr in self.config["network"]["internal_cidrs"]]
        self.external_nets = [ipaddress.IPv4Network(cidr) for cidr in self.config["network"]["external_cidrs"]]
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
        ]
        self.saas_domains = ["outlook.office365.com", "teams.microsoft.com", "sharepoint.com", "salesforce.com"]

    def _get_random_internal_ip(self) -> str:
        if self.use_dataset:
            # Pick a real internal-looking IP from dataset
            return self.loader.get_random_asset()
        subnet = random.choice(self.internal_nets)
        network_int = int(subnet.network_address)
        max_hosts = subnet.num_addresses - 1
        return str(ipaddress.IPv4Address(network_int + random.randint(1, max_hosts)))

    def _get_random_external_ip(self) -> str:
        if self.use_dataset:
            # In dataset mode, we can still use random external IPs for baseline "outbound" traffic
            # or pick another asset if we want to simulate internal movements.
            # Let's keep external IPs random unless it's an "internal" scan.
            pass
        subnet = random.choice(self.external_nets)
        network_int = int(subnet.network_address)
        max_hosts = subnet.num_addresses - 1
        return str(ipaddress.IPv4Address(network_int + random.randint(1, max_hosts)))
        
    def generate_baseline(self, start_time: datetime, duration_hours: int) -> List[Dict[str, Any]]:
        print("[-] Generating baseline traffic...")
        logs = []
        end_time = start_time + timedelta(hours=duration_hours)
        current_time = start_time
        
        # Pre-load dataset assets if available
        workstations = []
        servers = []
        if self.use_dataset:
            workstations = self.loader.get_devices()
            servers = self.loader.get_servers()
            # Fallback if classification was empty but assets exist
            if not workstations and not servers:
                workstations = self.loader.get_all_ips()

        # Pre-calculate services weights for fallback/random mode
        services = self.config["baseline"]["services"]
        service_choices = [s for s in services]
        service_weights = [s["weight"] for s in services]
        
        while current_time < end_time:
            # Random time increment
            dt = random.uniform(0.1, 2.0)
            current_time += timedelta(seconds=dt)
            if current_time > end_time: break
                
            burst_size = random.randint(1, 5)
            
            for _ in range(burst_size):
                # DEFAULT VALUES
                action = "accept"
                
                # LOGIC BRANCH: DATASET MODE VS RANDOM MODE
                if self.use_dataset and (workstations or servers):
                    # 70% Workstation Outbound, 30% Server Inbound (if servers exist)
                    is_server_inbound = (random.random() < 0.3) and bool(servers)
                    
                    if is_server_inbound:
                        # SCENARIO: External User -> Internal Server
                        # We hit a specific Open Port on the server
                        dst_ip = random.choice(servers)
                        open_ports = self.loader.get_open_ports(dst_ip)
                        
                        if open_ports:
                            svc = random.choice(open_ports)
                            dst_port = svc['port']
                            svc_name = svc['name']
                            proto = svc['proto']
                        else:
                            # Fallback if no specific ports found
                            dst_port = 80; svc_name = "http"; proto = 6
                        
                        src_ip = self._get_random_external_ip()
                        device_type = "external_user"
                        
                    else:
                        # SCENARIO: Internal Workstation -> External Web
                        # Browsing traffic
                        src_ip = random.choice(workstations) if workstations else "192.168.1.50"
                        dst_ip = self._get_random_external_ip()
                        device_type = "workstation"
                        
                        # Mostly HTTP/HTTPS
                        r = random.random()
                        if r < 0.6:
                            dst_port = 443; svc_name = "https"; proto = 6
                        elif r < 0.9:
                            dst_port = 80; svc_name = "http"; proto = 6
                        else:
                            # Occasional other traffic (DNS, etc)
                            dst_port = 53; svc_name = "DNS"; proto = 17
                            dst_ip = "8.8.8.8"
                
                else:
                    # RANDOM MODE (Legacy/Config based)
                    src_ip = self._get_random_internal_ip()
                    dst_ip = self._get_random_external_ip()
                    svc = random.choices(service_choices, weights=service_weights, k=1)[0]
                    dst_port = svc["port"]
                    proto = svc["proto"]
                    svc_name = svc["name"]
                    device_type = "workstation"

                # NAT/Port logic simulated loosely
                src_port = random.randint(10000, 65000)
                
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
                    "service": svc_name,
                    "action": action,
                    "policyid": 1 if device_type == "workstation" else 2, # 1=Outbound, 2=Inbound
                    "sentbyte": sent,
                    "rcvdbyte": rcvd,
                    "duration": random.randint(1, 60),
                    "user": f"user-{random.randint(1, 50)}" if device_type == "workstation" else "N/A",
                    "device_type": device_type,
                    "level": "notice",
                    "logid": "0000000013",
                    "srccountry": "Reserved" if ipaddress.ip_address(src_ip).is_private else "United States",
                    "dstcountry": "United States",
                    "agent": random.choice(self.user_agents) if "http" in svc_name else "N/A"
                }
                
                # SaaS Simulation (Randomly override destination for 5% of web traffic)
                if device_type == "workstation" and "http" in svc_name and random.random() < 0.05:
                    log["dstdomain"] = random.choice(self.saas_domains)
                    
                logs.append(log)
                
        print(f"[-] Generated {len(logs)} baseline events.")
        return logs

    def run(self, counts=None, time_offset_mins=0):
        """
        Runs the simulation. 
        'counts' can be a dict specifying exactly how many of each to generate.
        'time_offset_mins' pushes the end of the simulation window into the past.
        """
        now = datetime.now() - timedelta(minutes=time_offset_mins)
        # We align the simulation to END at 'now'
        duration = self.config["simulation"]["duration_hours"]
        start_time = now - timedelta(hours=duration)
        
        all_logs = []
        
        if counts:
            # GRANULAR MODE

            # --- GRANULAR BASELINE BY PROTOCOL ---
            if counts.get('http', 0) > 0:
                print(f"[-] Generating {counts['http']} HTTP baseline events...")
                for _ in range(counts['http']):
                    # Simulate HTTP/HTTPS explicitly
                    svc = {"port": 443, "name": "https", "proto": 6} if random.random() < 0.7 else {"port": 80, "name": "http", "proto": 6}
                    all_logs.append(self._generate_single_log(svc, start_time, duration))

            if counts.get('dns_normal', 0) > 0:
                 print(f"[-] Generating {counts['dns_normal']} DNS baseline events...")
                 svc = {"port": 53, "name": "DNS", "proto": 17}
                 for _ in range(counts['dns_normal']):
                     all_logs.append(self._generate_single_log(svc, start_time, duration))

            if counts.get('ssh_normal', 0) > 0:
                 print(f"[-] Generating {counts['ssh_normal']} SSH baseline events...")
                 svc = {"port": 22, "name": "SSH", "proto": 6}
                 for _ in range(counts['ssh_normal']):
                    all_logs.append(self._generate_single_log(svc, start_time, duration))

            # Generic Baseline (Mixed)
            if counts.get('baseline', 0) > 0:
                print(f"[-] Generating {counts['baseline']} mixed baseline events...")
                services = self.config["baseline"]["services"]
                service_choices = [s for s in services]
                service_weights = [s["weight"] for s in services]
                
                for _ in range(counts['baseline']):
                    svc = random.choices(service_choices, weights=service_weights, k=1)[0]
                    all_logs.append(self._generate_single_log(svc, start_time, duration))

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
    parser.add_argument("--baseline", type=int, default=0, help="Number of mixed baseline logs")
    parser.add_argument("--http", type=int, default=0, help="Number of HTTP logs")
    parser.add_argument("--dns_normal", type=int, default=0, help="Number of Normal DNS logs")
    parser.add_argument("--ssh_normal", type=int, default=0, help="Number of Normal SSH logs")
    
    parser.add_argument("--ssh", type=int, default=0, help="Number of SSH attack logs to generate")
    parser.add_argument("--dns", type=int, default=0, help="Number of DNS attack logs to generate")
    parser.add_argument("--beacon", type=int, default=0, help="Number of Beacon logs to generate")
    parser.add_argument("--seed", type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument("--offset", type=int, default=0, help="Time offset in minutes (how many minutes ago the window ends)")
    args = parser.parse_args()
    
    if args.seed is not None:
        random.seed(args.seed)
        print(f"[-] Random seed set to: {args.seed}")
    
    gen = TrafficGenerator(args.config)
    # If any specific counts are provided, use granular mode
    if args.baseline or args.ssh or args.dns or args.beacon or args.http or args.dns_normal or args.ssh_normal:
        granular_counts = {
            "baseline": args.baseline,
            "ssh": args.ssh,
            "dns": args.dns,
            "beacon": args.beacon,
            "http": args.http,
            "dns_normal": args.dns_normal,
            "ssh_normal": args.ssh_normal
        }
        gen.run(granular_counts, time_offset_mins=args.offset)
    else:
        gen.run(time_offset_mins=args.offset)
