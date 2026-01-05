from dataclasses import dataclass, field
from typing import Optional, List
import random
import datetime

@dataclass
class LogParams:
    # Base Fields
    timestamp: datetime.datetime
    log_type: str
    source: str = "simulation"
    host: str = "workstation-01"
    severity: str = "INFO"
    
    # Network
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None
    bytes_sent: Optional[int] = None
    bytes_received: Optional[int] = None
    duration: Optional[int] = None
    direction: Optional[str] = None
    device: Optional[str] = None
    
    # Auth
    user: Optional[str] = None
    auth_type: Optional[str] = None
    auth_result: Optional[str] = None
    failure_reason: Optional[str] = None
    location: Optional[str] = None
    
    # Endpoint
    process_name: Optional[str] = None
    process_id: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    hash_val: Optional[str] = None # 'hash' is reserved
    integrity_level: Optional[str] = None
    
    # Application / Web
    http_method: Optional[str] = None
    url: Optional[str] = None
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    request_size: Optional[int] = None
    response_size: Optional[int] = None
    session_id: Optional[str] = None
    client_ip: Optional[str] = None # duplicate of src_ip often
    
    # Asset
    asset_id: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os: Optional[str] = None
    os_version: Optional[str] = None
    role: Optional[str] = None
    criticality: Optional[str] = None
    last_seen: Optional[str] = None
    
    # Alert
    alert_name: Optional[str] = None
    detection_engine: Optional[str] = None
    action_taken: Optional[str] = None
    confidence: Optional[str] = None
    
    # DNS
    query: Optional[str] = None
    query_type: Optional[str] = None
    response: Optional[str] = None
    rcode: Optional[str] = None
    ttl: Optional[int] = None
    resolver: Optional[str] = None
    
    # Cloud
    cloud_provider: Optional[str] = None
    account_id: Optional[str] = None
    api_call: Optional[str] = None
    resource: Optional[str] = None
    region: Optional[str] = None
    result: Optional[str] = None
    
    # Additional
    msg: Optional[str] = None
    src_country: Optional[str] = None
    dst_country: Optional[str] = None
    service: Optional[str] = None
    policyid: Optional[int] = None
    device_type: Optional[str] = None
    
    def to_dict(self):
        # Convert to dict, filtering Nones usually handled by consumer but here we keep all for schema
        # We handle renaming 'hash_val' -> 'hash'
        d = {k: v for k, v in self.__dict__.items() if v is not None}
        if 'hash_val' in d:
            d['hash'] = d.pop('hash_val')
        return d

class DomainGenerator:
    def __init__(self):
        pass

    def generate_network_log(self, ts):
        return LogParams(
            timestamp=ts,
            log_type="network",
            src_ip=f"192.168.1.{random.randint(2, 254)}",
            dst_ip=f"10.0.0.{random.randint(2, 254)}",
            src_port=random.randint(1024, 65535),
            dst_port=random.choice([80, 443, 22, 53]),
            protocol=random.choice(["TCP", "UDP"]),
            action=random.choice(["ALLOW", "DENY"]),
            bytes_sent=random.randint(100, 5000),
            bytes_received=random.randint(100, 50000),
            duration=random.randint(1, 100),
            direction=random.choice(["inbound", "outbound"]),
            device="Firewall-01"
        )

    def generate_auth_log(self, ts):
        user = f"user_{random.randint(1, 50)}"
        res = random.choice(["SUCCESS", "FAILURE"])
        reason = "Bad Password" if res == "FAILURE" else None
        return LogParams(
            timestamp=ts,
            log_type="authentication",
            user=user,
            src_ip=f"192.168.1.{random.randint(2, 254)}",
            auth_type="Kerberos",
            auth_result=res,
            failure_reason=reason,
            device="DC-01",
            location="Office-HQ"
        )
        
    def generate_endpoint_log(self, ts):
        proc = random.choice(["svchost.exe", "powershell.exe", "cmd.exe", "chrome.exe"])
        return LogParams(
            timestamp=ts,
            log_type="endpoint",
            host=f"WORKSTATION-{random.randint(1, 20)}",
            user=f"user_{random.randint(1, 50)}",
            process_name=proc,
            process_id=str(random.randint(1000, 9999)),
            parent_process="explorer.exe",
            command_line=f"{proc} -argument",
            file_path=f"C:\\Windows\\System32\\{proc}",
            hash_val="a1b2c3d4e5f6...",
            integrity_level=random.choice(["Medium", "High", "System"])
        )

    def generate_web_log(self, ts):
        method = random.choice(["GET", "POST"])
        url = random.choice(["/login", "/api/data", "/home", "/search"])
        status = random.choice([200, 200, 200, 404, 403, 500])
        return LogParams(
            timestamp=ts,
            log_type="application",
            client_ip=f"192.168.1.{random.randint(2, 254)}",
            http_method=method,
            url=url,
            status_code=status,
            user_agent="Mozilla/5.0...",
            request_size=random.randint(100, 1000),
            response_size=random.randint(500, 5000),
            session_id=f"sess_{random.randint(10000, 99999)}"
        )
        
    def generate_asset_log(self, ts):
        a_id = f"AST-{random.randint(1000, 9999)}"
        return LogParams(
            timestamp=ts,
            log_type="asset",
            asset_id=a_id,
            hostname=f"SRV-{random.randint(1, 10)}",
            ip_address=f"10.0.0.{random.randint(10, 50)}",
            mac_address="00:11:22:33:44:55",
            os=random.choice(["Windows Server 2019", "Ubuntu 20.04", "CentOS 7"]),
            role=random.choice(["Database", "Web Server", "Domain Controller"]),
            criticality=random.choice(["High", "Medium", "Low"]),
            last_seen=str(ts)
        )
        
    def generate_security_alert(self, ts):
        alert = random.choice(["Brute Force Attempt", "Malware Detected", "Suspicious PowerShell"])
        sev = random.choice(["High", "Medium", "Low"])
        return LogParams(
            timestamp=ts,
            log_type="security_alert",
            alert_name=alert,
            severity=sev,
            detection_engine="Sigma",
            src_ip=f"192.168.1.{random.randint(2, 254)}",
            dst_ip=f"10.0.0.{random.randint(2, 254)}",
            user=f"user_{random.randint(1, 50)}",
            action_taken=random.choice(["Blocked", "Alerted only"]),
            confidence="High"
        )
        
    def generate_dns_log(self, ts):
        domain = random.choice(["google.com", "evil.com", "microsoft.com", "yahoo.com"])
        return LogParams(
            timestamp=ts,
            log_type="dns",
            client_ip=f"192.168.1.{random.randint(2, 254)}",
            query=domain,
            query_type="A",
            response="1.2.3.4",
            rcode="NOERROR",
            ttl=300,
            resolver="8.8.8.8"
        )
        
    def generate_cloud_log(self, ts):
        action = random.choice(["ConsoleLogin", "CreateBucket", "RunInstances", "DeleteGroup"])
        return LogParams(
            timestamp=ts,
            log_type="cloud",
            cloud_provider="AWS",
            account_id="123456789012",
            api_call=action,
            resource=f"arn:aws:s3:::bucket-{random.randint(1,99)}",
            user="admin-user",
            src_ip=f"203.0.113.{random.randint(1, 50)}",
            region="us-east-1",
            result=random.choice(["Success", "AccessDenied"])
        )
