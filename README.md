# IoT Security Monitoring Tool

A lightweight, single-host security monitoring tool for IoT environments.

## Architecture
- **Ingestion**: File-based (JSON/XML)
- **Detection**: Rule-based (DNS Tunneling, SSH Abuse, Beaconing)
- **Backend**: Flask API
- **Database**: MySQL (Local)
- **Visualization**: Grafana (Local)

## Quick Start (Local)

1. **Setup Database**:
   Create the database and tables using `schema.sql` in your local MySQL instance.
   ```powershell
   Get-Content schema.sql | mysql -u root -p
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Start API**:
   ```bash
   python app.py
   ```

4. **Ingest Logs**:
   ```bash
   curl -X POST -F "file=@test_logs.json" http://localhost:5000/ingest
   ```

5. **View Alerts**:
   - API: `http://localhost:5000/alerts`
   - Grafana: Connect to local MySQL `iot_security` db.

## Directory Structure
- `api/`: Flask routes and database connection
- `detection/`: Detection logic modules
- `ingestor.py`: Log parsing logic
- `schema.sql`: Database schema output
- `requirements.txt`: Python dependencies
