from flask import Blueprint, request, jsonify
from ingestor import LogIngestor
from detection.engine import run_detection_pipeline, format_alert_object
from api.db import get_db_connection
import os
import tempfile

api_bp = Blueprint('api', __name__)

@api_bp.route('/ingest', methods=['POST'])
def ingest_logs():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Save temp file for processing
    fd, path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, 'wb') as tmp:
            file.save(tmp)
        
        # 1. Parse & Normalize
        ingestor = LogIngestor()
        normalized_logs = ingestor.parse_log_file(path)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        processed_count = 0
        alerts_generated = 0

        for log in normalized_logs:
            # 2. Store Normalized Log
            sql_log = "INSERT INTO logs (timestamp, src_ip, dst_ip, device_type, protocol, action, raw_log) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            cursor.execute(sql_log, (log['timestamp'], log['src_ip'], log['dst_ip'], log['device_type'], log['protocol'], log['action'], log['raw_log']))
            log_id = cursor.lastrowid

            # 3. Detect
            detections = run_detection_pipeline(log)
            
            for d in detections:
                alert_data = format_alert_object(d, log, log_id)
                # 4. Store Alert
                sql_alert = "INSERT INTO alerts (severity, detection_type, src_ip, device, timestamp, raw_log_reference) VALUES (%s, %s, %s, %s, %s, %s)"
                cursor.execute(sql_alert, (alert_data['severity'], alert_data['detection_type'], alert_data['src_ip'], alert_data['device'], alert_data['timestamp'], log_id))
                alerts_generated += 1
            
            processed_count += 1
        
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            "status": "success", 
            "logs_processed": processed_count, 
            "alerts_generated": alerts_generated
        }), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        os.remove(path)

@api_bp.route('/alerts', methods=['GET'])
def get_alerts():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 100")
        alerts = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(alerts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@api_bp.route('/stats', methods=['GET'])
def get_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Simple stats for dashboard overview if needed directly via API
        cursor.execute("SELECT COUNT(*) as total_alerts FROM alerts")
        total_alerts = cursor.fetchone()['total_alerts']
        
        cursor.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
        severity_counts = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "total_alerts": total_alerts,
            "severity_counts": severity_counts
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
