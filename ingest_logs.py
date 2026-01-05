import os
import json
from ingestor import LogIngestor
from detection.engine import run_detection_pipeline, format_alert_object
from api.db import get_db_connection

def ingest_direct(file_path):
    print(f"[*] Starting ingestion for {file_path}")
    if not os.path.exists(file_path):
        print(f"[!] Error: {file_path} not found.")
        return

    ingestor = LogIngestor()
    normalized_logs = ingestor.parse_log_file(file_path)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    processed_count = 0
    alerts_generated = 0

    print(f"[*] Processing {len(normalized_logs)} logs...")
    for log in normalized_logs:
        try:
            # 1. Store Normalized Log
            sql_log = """INSERT INTO logs 
                (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, service, action, policyid, sentbyte, rcvdbyte, duration, user, device_type, level, logid, qname, raw_log) 
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
            
            cursor.execute(sql_log, (
                log.get('timestamp'), 
                log.get('src_ip'), 
                log.get('dst_ip'), 
                log.get('src_port'),
                log.get('dst_port'),
                log.get('protocol'), 
                log.get('service'),
                log.get('action'),
                log.get('policyid', 1),
                log.get('sentbyte', 0),
                log.get('rcvdbyte', 0),
                log.get('duration', 0),
                log.get('user', 'N/A'),
                log.get('device_type'),
                log.get('level', 'notice'),
                log.get('logid'),
                log.get('qname'),
                log.get('raw_log')
            ))
            log_id = cursor.lastrowid

            # 2. Detect Anomalies
            detections = run_detection_pipeline(log)
            
            for d in detections:
                alert_data = format_alert_object(d, log, log_id)
                # 3. Store Alert
                sql_alert = "INSERT INTO alerts (severity, detection_type, src_ip, device, timestamp, raw_log_reference, mitre_tactic, mitre_technique) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
                cursor.execute(sql_alert, (alert_data['severity'], alert_data['detection_type'], alert_data['src_ip'], alert_data['device'], alert_data['timestamp'], log_id, alert_data['mitre_tactic'], alert_data['mitre_technique']))
                alerts_generated += 1
            
            processed_count += 1
            
            if processed_count % 100 == 0:
                conn.commit()
                print(f"[*] Committed {processed_count} logs...")
                
        except Exception as e:
            print(f"[!] Error processing log: {e}")
            import traceback
            traceback.print_exc()
            continue
    
    conn.commit()
    cursor.close()
    conn.close()
    
    # 4. Post-Ingestion Correlation (Batch / Multi-Event)
    # 4. Post-Ingestion Correlation (Batch / Multi-Event)
    # print("[*] Running Post-Ingestion Correlation checks...")
    # try:
    #     from detection.dns import analyze_subdomain_volume
    #     # Re-fetch recent DNS logs
    #     conn = get_db_connection()
    #     df = pd.read_sql("SELECT raw_log_reference, timestamp, qname as dns_qname, src_ip FROM logs WHERE protocol=17 AND qname IS NOT NULL ORDER BY id DESC LIMIT 2000", conn)
    #     conn.close()
    #     
    #     if not df.empty:
    #         logs_for_analysis = df.to_dict('records')
    #         batch_alerts = analyze_subdomain_volume(logs_for_analysis, threshold=5) # stricter threshold for demo
    #         
    #         if batch_alerts:
    #             print(f"[!] Found {len(batch_alerts)} correlation alerts.")
    #             conn = get_db_connection()
    #             c = conn.cursor()
    #             for a in batch_alerts:
    #                 # Deduplicate: Only insert if not recently alerted for same domain
    #                 # For simplicity in this demo, we just insert.
    #                 sql = "INSERT INTO alerts (severity, detection_type, src_ip, device, timestamp, mitre_tactic, mitre_technique) VALUES (%s, %s, %s, %s, NOW(), %s, %s)"
    #                 # We might not have a single source IP for a volume alert, but let's grab one from the logs or use 'Multiple'
    #                 # analyze_subdomain_volume doesn't return src_ip in the alert dict by default, let's fix that or use generic.
    #                 c.execute(sql, (a['severity'], a['type'], 'Multiple', 'Network', a['mitre_tactic'], a['mitre_technique']))
    #             conn.commit()
    #             conn.close()
    #             alerts_generated += len(batch_alerts)
    # 
    # except Exception as e:
    #     print(f"[!] Correlation error: {e}")

    print(f"[+] Ingestion complete: {processed_count} logs processed, {alerts_generated} alerts generated.")

if __name__ == "__main__":
    # Look for the JSON file generated by traffic_generator.py
    log_file = "simulated_fortigate_logs.json"
    ingest_direct(log_file)
