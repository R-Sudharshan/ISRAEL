import unittest
from datetime import datetime, timedelta
from detection.dns import detect_dns_tunneling
from detection.ssh import detect_ssh_abuse
from detection.beacon import detect_beaconing

class TestDetectionEngine(unittest.TestCase):
    
    def test_dns_tunneling(self):
        # Test normal domain
        self.assertIsNone(detect_dns_tunneling("google.com"))
        
        # Test long query / high entropy
        long_domain = "a" * 60 + ".example.com"
        alert = detect_dns_tunneling(long_domain)
        self.assertIsNotNone(alert)
        self.assertEqual(alert['type'], "DNS Tunneling")
        self.assertIn("High query length", str(alert['indicators']))

    def test_ssh_abuse(self):
        # Test normal
        normal_log = {"protocol": "ssh", "device_type": "laptop", "action": "login_success"}
        self.assertIsNone(detect_ssh_abuse(normal_log))
        
        # Test IoT device SSH
        iot_log = {"protocol": "ssh", "device_type": "camera", "action": "login_success", "src_ip": "1.1.1.1"}
        alert = detect_ssh_abuse(iot_log)
        self.assertIsNotNone(alert)
        self.assertIn("Unexpected SSH traffic", str(alert['indicators']))
        
        # Test Failed login
        fail_log = {"protocol": "ssh", "device_type": "server", "action": "login_failed", "src_ip": "1.1.1.1"}
        alert_fail = detect_ssh_abuse(fail_log)
        self.assertIsNotNone(alert_fail)
        self.assertIn("SSH Authentication Failure", str(alert_fail['indicators']))

    def test_beaconing(self):
        # Fixed interval every 10 seconds
        base_time = datetime.now()
        timestamps = [base_time + timedelta(seconds=10*x) for x in range(10)]
        
        alert = detect_beaconing(timestamps)
        self.assertIsNotNone(alert)
        self.assertEqual(alert['type'], "Beaconing Detected")
        self.assertAlmostEqual(alert['average_interval'], 10.0, delta=0.1)

        # Irregular interval
        irregular = [base_time, base_time + timedelta(seconds=10), base_time + timedelta(seconds=45), base_time + timedelta(seconds=48)]
        self.assertIsNone(detect_beaconing(irregular))

if __name__ == '__main__':
    unittest.main()
