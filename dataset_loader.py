import pandas as pd
import random
import os
from typing import List, Dict, Any

class DatasetLoader:
    """
    Loads and parses the provided network scan dataset to ground simulations in reality.
    """
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        self.azure_hosts_path = os.path.join(data_dir, "data1", "azure_hosts.csv")
        self.azure_services_path = os.path.join(data_dir, "data1", "azure_services.csv")
        self.onprem_services_path = os.path.join(data_dir, "data1", "on-prem_services.csv")
        
        self.assets = {} # IP -> Dict of info
        self.services = {} # IP -> List of service dicts
        
        self._load_all()

    def _load_all(self):
        # Load Hosts
        if os.path.exists(self.azure_hosts_path):
            df_hosts = pd.read_csv(self.azure_hosts_path)
            self._process_hosts(df_hosts)

        # Load Azure Services
        if os.path.exists(self.azure_services_path):
            df_azure = pd.read_csv(self.azure_services_path)
            self._process_services(df_azure, "azure")
            
        # Load On-Prem Services
        if os.path.exists(self.onprem_services_path):
            df_onprem = pd.read_csv(self.onprem_services_path)
            self._process_services(df_onprem, "on-prem")
            
        print(f"[DatasetLoader] Loaded {len(self.assets)} assets from dataset.")

    def _process_hosts(self, df):
        # Columns: address,mac,name,os_name,os_flavor,os_sp,purpose,info,comments
        for _, row in df.iterrows():
            ip = row['address']
            self.assets[ip] = {
                "os": row['os_name'] if pd.notna(row['os_name']) else "Unknown",
                "purpose": row['purpose'] if pd.notna(row['purpose']) else "device",
                "type": "azure" # derived from file
            }

    def _process_services(self, df, asset_type):
        # Columns: host,port,proto,name,state,info
        for _, row in df.iterrows():
            host = row['host']
            if host not in self.services:
                self.services[host] = []
            
            # Ensure host exists in assets even if not in hosts file
            if host not in self.assets:
                self.assets[host] = {"os": "Unknown", "purpose": "device", "type": asset_type}
            
            self.services[host].append({
                "port": int(row['port']),
                "proto": 17 if row['proto'].lower() == 'udp' else 6,
                "name": row['name'],
                "state": row['state'],
                "info": row['info'],
                "type": asset_type
            })

    def get_all_ips(self) -> List[str]:
        return list(self.assets.keys())

    def get_random_asset(self) -> str:
        ips = self.get_all_ips()
        return random.choice(ips) if ips else "192.168.1.1"
    
    def get_servers(self) -> List[str]:
        """Return IPs classified as servers or having open server ports."""
        return [ip for ip, data in self.assets.items() if data['purpose'] == 'server']

    def get_devices(self) -> List[str]:
        """Return IPs classified as devices/workstations."""
        return [ip for ip, data in self.assets.items() if data['purpose'] == 'device']

    def get_open_ports(self, ip: str) -> List[Dict[str, Any]]:
        if ip not in self.services: return []
        return [s for s in self.services[ip] if s['state'] == 'open']

    def get_vulnerable_targets(self, port: int) -> List[str]:
        """Finds hosts that have a specific port open or filtered."""
        targets = []
        for ip, svcs in self.services.items():
            if any(s['port'] == port for s in svcs):
                targets.append(ip)
        return targets

if __name__ == "__main__":
    # Test loader
    loader = DatasetLoader("dataset")
    print(f"Random Asset: {loader.get_random_asset()}")
    targets = loader.get_vulnerable_targets(22)
    print(f"Hosts with SSH: {len(targets)}")
