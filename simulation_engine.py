from datetime import datetime, timedelta
import random
from typing import List, Dict, Any, Generator

from entities import EntityManager, User, Device
from activities import Activity, NormalWebRequest, IoTHeartbeat, SSHBruteForce, MaliciousFileUpload, DNSExfiltration
from log_schema import FIREWALL_SCHEMA, WEB_ACCESS_SCHEMA, IOT_SCHEMA, validate_entry, LogSchemaValidationException
from dataset_loader import DatasetLoader

class SimulationEngine:
    def __init__(self, config: Dict[str, Any], dataset_loader: DatasetLoader = None):
        self.config = config
        self.entity_manager = EntityManager()
        self.current_time = datetime.now()
        self.loader = dataset_loader or DatasetLoader("dataset")
        
        # Initialize Entities
        self._initialize_entities()

    def _initialize_entities(self):
        # Create some random users and devices based on dataset or defaults
        # This is a simplified population for now
        self.entity_manager.users = [
            User(id="u1", username="alice.smith", department="HR", role="user"),
            User(id="u2", username="bob.jones", department="IT", role="admin"),
            User(id="u3", username="charlie.d", department="Sales", role="user"),
        ]
        
        # Load devices from dataset if possible
        dataset_devices = self.loader.get_devices()
        for i, ip in enumerate(dataset_devices[:20]): # Take first 20 for now
            self.entity_manager.devices.append(
                Device(id=f"d{i}", ip_address=ip, mac_address="00:00:00:00:00:00", hostname=f"pc-{i}", type="workstation", os_info="Windows 10")
            )
            
        if not self.entity_manager.devices:
             # Fallback
             self.entity_manager.devices.append(Device(id="d1", ip_address="192.168.1.50", mac_address="", hostname="pc-default", type="workstation", os_info="Win10"))

    def run(self, start_time: datetime, duration_hours: int) -> Generator[Dict[str, Any], None, None]:
        self.current_time = start_time
        end_time = start_time + timedelta(hours=duration_hours)
        
        timeline_events = []
        
        # 1. Schedule Baseline Activities
        # Simple algorithm: random recurring events
        t = start_time
        while t < end_time:
            # Users browsing web
            if 8 <= t.hour <= 18:
                count = random.randint(1, 5)
                for _ in range(count):
                    user = self.entity_manager.get_random_user()
                    device = self.entity_manager.get_random_device()
                    if user and device:
                        activity = NormalWebRequest(
                            start_time=t + timedelta(seconds=random.randint(0, 59)),
                            user=user,
                            src_device=device,
                            dest_ip="142.250.180.14", # Google
                            url="https://www.google.com/search?q=test"
                        )
                        timeline_events.append(activity)
            
            # IoT Heartbeats (24/7)
            # Assuming we have some IoT devices, or just simulate one
            iot_dev = Device(id="iot1", ip_address="192.168.10.5", mac_address="", hostname="cam-01", type="iot-camera", os_info="Linux")
            timeline_events.append(IoTHeartbeat(t, iot_dev, "192.168.1.200"))
            
            t += timedelta(minutes=1)
            
        # 2. Schedule Attack Activities (if configured)
        # For now, manually inject one attack for testing
        attack_t = start_time + timedelta(minutes=15)
        attacker = self.entity_manager.attackers[0] if self.entity_manager.attackers else None
        # Create a mock attacker if none
        from entities import Attacker
        mock_attacker = Attacker(id="a1", ip_address="45.33.22.11", known_tools=["hydra"], target_profile="random")
        
        timeline_events.append(SSHBruteForce(attack_t, mock_attacker, "192.168.1.10"))
        
        # 3. Sort events by start time
        timeline_events.sort(key=lambda x: x.start_time)
        
        # 4. Generate and Validate
        for activity in timeline_events:
            if activity.start_time > end_time:
                break
                
            raw_logs = activity.generate_logs()
            for log in raw_logs:
                if self._validate_log(log):
                    yield log

    def _validate_log(self, log: Dict[str, Any]) -> bool:
        # 1. Determine Schema based on log content (naive check for now)
        schema = None
        if log.get("type") == "traffic":
            schema = FIREWALL_SCHEMA
        elif log.get("type") == "utm" and log.get("subtype") == "webfilter":
            schema = WEB_ACCESS_SCHEMA
        # ... others
        
        if schema:
            try:
                validate_entry(log, schema)
                return True
            except LogSchemaValidationException as e:
                print(f"[Validation Failed] {e} | Log: {log}")
                return False
        
        # If no schema matched, maybe let it pass or strict fail? 
        # For this system: Strict Fail if we want "Industry Grade".
        # But we might have logs not yet covered by schema.
        # Let's Log warning and pass for minimal viability, or False to be strict.
        # User said "Logs that fail → discarded."
        print(f"[Validation Warning] No matching schema for log type: {log.get('type')}/{log.get('subtype')}")
        return False

