from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
import random

@dataclass
class Entity:
    id: str

@dataclass
class User(Entity):
    username: str
    department: str
    role: str # admin, user, contractor
    working_hours: tuple = (9, 17) # Start, End hour
    assigned_ips: List[str] = field(default_factory=list)

    def is_working_hour(self, current_time: datetime) -> bool:
        return self.working_hours[0] <= current_time.hour < self.working_hours[1]

@dataclass
class Device(Entity):
    ip_address: str
    mac_address: str
    hostname: str
    type: str # workstation, server, printer, iot
    os_info: str
    state: str = "online" # online, offline, compromised

    def is_active(self) -> bool:
        return self.state == "online" or self.state == "compromised"

@dataclass
class NetworkSession(Entity):
    # Tracks an active TCP/UDP session
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int # 6, 17
    start_time: datetime
    last_activity: datetime
    state: str # established, closed, time_wait

@dataclass
class Attacker(Entity):
    ip_address: str
    known_tools: List[str]
    target_profile: str # random, persistent
    current_campaign: Optional[str] = None

class EntityManager:
    def __init__(self):
        self.users: List[User] = []
        self.devices: List[Device] = []
        self.sessions: List[NetworkSession] = []
        self.attackers: List[Attacker] = []

    def load_from_dataset(self, dataset_loader):
        # Integration with DatasetLoader to populate entities
        # This will be called by the Application initialization
        pass

    def get_random_user(self) -> Optional[User]:
        if not self.users: return None
        return random.choice(self.users)

    def get_random_device(self, type_filter: str = None) -> Optional[Device]:
        candidates = self.devices
        if type_filter:
            candidates = [d for d in self.devices if d.type == type_filter]
        if not candidates: return None
        return random.choice(candidates)
