import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from api.db import get_db_connection
import datetime
import time

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Forloggen",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 1.1 AUTH MANAGER ---
from auth_manager import AuthManager
from streamlit_cookies_controller import CookieController

# Initialize controller
controller = CookieController()

# Safe Session State Init
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_role = None
    st.session_state.username = None
    st.session_state.user_id = None

# --- COOKIE CHECK ---
if not st.session_state.logged_in:
    saved_token = controller.get("forloggen_user")
    if saved_token:
        try:
            user_id = AuthManager.get_user_id(saved_token)
            if user_id:
                conn = get_db_connection()
                c = conn.cursor(dictionary=True)
                c.execute("SELECT * FROM users WHERE username = %s", (saved_token,))
                u = c.fetchone()
                c.close()
                conn.close()
                
                if u:
                    st.session_state.logged_in = True
                    st.session_state.username = u['username']
                    st.session_state.user_role = u['role']
                    st.session_state.user_id = u['id']
        except Exception as e:
            pass

# --- LOGIN PAGE LOGIC ---
if not st.session_state.logged_in:
    st.markdown("""
    <style>
        .stApp { background-color: #f6f8fa; }
        .login-box {
            max-width: 400px;
            margin: 100px auto;
            padding: 30px;
            background: white;
            border: 1px solid #d0d7de;
            border-radius: 6px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        .login-header {
            text-align: center;
            margin-bottom: 20px;
            color: #24292f;
        }
    </style>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div class="login-header"><h2>FORLOGGEN ID</h2><p>Restricted Access</p></div>', unsafe_allow_html=True)
        with st.form("login_form"):
            user_input = st.text_input("Username")
            pass_input = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign In", use_container_width=True, type="primary")
            
            if submitted:
                auth = AuthManager.login(user_input, pass_input)
                if auth:
                    st.session_state.logged_in = True
                    st.session_state.username = auth['username']
                    st.session_state.user_role = auth['role']
                    st.session_state.user_id = auth['id']
                    
                    # Set Cookie (Expires in 7 days)
                    controller.set("forloggen_user", auth['username'], max_age=60*60*24*7)
                    
                    st.toast(f"Welcome back, {auth['username']}")
                    st.rerun()
                else:
                    st.error("Invalid credentials")
    
    st.stop()

# --- 2. CUSTOM CSS (ENTERPRISE WHITE THEME) ---
st.markdown("""
<style>
    /* Global Background - Professional White Theme */
    .stApp {
        background-color: #f6f8fa; /* Light Gray Background */
        color: #24292f;            /* Dark Gray Text */
        font-family: 'Segoe UI', 'Roboto', sans-serif;
    }
    
    /* Technical Density: Reset Streamlit Padding */
    .block-container {
        padding: 4rem 1rem 1.5rem 1rem !important;
        max-width: 100%;
    }
    
    /* Typography: High Contrast */
    h1, h2, h3, h4, h5, h6 {
        color: #24292f !important;
        font-weight: 600 !important;
        margin-bottom: 0.5rem !important;
    }
    
    /* Sidebar: Clean Light Navigation */
    [data-testid="stSidebar"] {
        background-color: #ffffff;
        border-right: 1px solid #d0d7de;
    }
    [data-testid="stSidebar"] * {
        color: #57606a !important; /* Secondary Text */
    }
    
    /* The "Module" Container - Clean White on Light Gray */
    .dashboard-module {
        background-color: #ffffff;
        border: 1px solid #d0d7de;
        padding: 12px;
        margin-bottom: 12px;
        color: #24292f;
        box-shadow: 0 1px 3px rgba(31,35,40,0.04);
    }
    
    .module-sharp { border-radius: 2px; }
    .module-soft { border-radius: 6px; }
    .module-round { border-radius: 10px; }

    .module-header {
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        color: #57606a;
        border-bottom: 1px solid #d0d7de;
        padding-bottom: 6px;
        margin-bottom: 10px;
        display: flex;
        justify-content: space-between;
    }
    
    .data-row {
        display: flex;
        justify-content: space-between;
        font-size: 12px;
        padding: 4px 0;
        border-bottom: 1px solid #f6f8fa;
        font-family: 'Consolas', 'Monaco', monospace;
    }
    .data-label { color: #57606a; }
    .data-val { color: #0969da; font-weight: 500; } /* Professional Blue */
    
    .status-pill {
        padding: 2px 8px;
        font-size: 10px;
        font-weight: 600;
        border-radius: 12px;
    }
    .status-ok { background: #dafbe1; color: #1a7f37; border: 1px solid #1a7f37; }
    .status-warn { background: #fff8c5; color: #9a6700; border: 1px solid #9a6700; }
    .status-crit { background: #ffebe9; color: #cf222e; border: 1px solid #cf222e; }

    .top-header {
        font-size: 20px;
        color: #24292f;
        font-weight: 700;
        margin-bottom: 15px;
        letter-spacing: -0.5px;
    }

    .terminal-mono, .terminal-text {
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 11px;
        color: #57606a;
    }

    /* Streamlit Button Overrides for Light Theme */
    .stButton>button {
        border-radius: 6px !important;
        font-size: 12px !important;
        font-weight: 500 !important;
    }
    /* Primary Button: Professional Blue */
    button[data-testid="baseButton-primary"] {
        background-color: #0969da !important;
        border: 1px solid #0969da !important;
        color: #ffffff !important;
    }
    button[data-testid="baseButton-primary"]:hover {
        background-color: #0550ae !important;
        border-color: #0550ae !important;
    }
    /* Secondary Button: Clean Gray */
    button[data-testid="baseButton-secondary"] {
        background-color: #ffffff !important;
        color: #24292f !important;
        border: 1px solid #d0d7de !important;
    }
    button[data-testid="baseButton-secondary"]:hover {
        background-color: #f6f8fa !important;
        border-color: #afb8c1 !important;
    }
</style>
""", unsafe_allow_html=True)

# --- 3. DATA FETCHING ---
@st.cache_data(ttl=5) # Reduced TTL for faster updates
def get_dashboard_data():
    conn = get_db_connection()
    try:
        # Logs - Ensure we get the latest by both timestamp and chronological order
        df_logs = pd.read_sql("SELECT * FROM logs ORDER BY timestamp DESC, id DESC LIMIT 5000", conn)
        # Alerts
        df_alerts = pd.read_sql("SELECT * FROM alerts ORDER BY timestamp DESC, alert_id DESC LIMIT 1000", conn)
        
        # Aggregate Metrics (PRODUCTION LEVEL LOGIC)
        stats = {
            "total_logs": 0,
            "total_alerts": 0,
            "total_bytes": 0,
            "active_sessions": 0,
            "active_users": 0,
            "active_policies": 0,
            "throughput_kbps": 0.0,
            "cpu_usage": 12, # Baseline
            "ram_usage": 34  # Baseline
        }

        if not df_logs.empty:
            stats["total_logs"] = len(df_logs)
            stats["total_bytes"] = int(df_logs['sentbyte'].sum() + df_logs['rcvdbyte'].sum())
            stats["active_sessions"] = len(df_logs)
            if 'user' in df_logs.columns:
                stats["active_users"] = df_logs[df_logs['user'] != 'N/A']['user'].nunique()
            if 'policyid' in df_logs.columns:
                stats["active_policies"] = df_logs['policyid'].nunique()
            
            # Throughput kbps
            df_logs['timestamp'] = pd.to_datetime(df_logs['timestamp'])
            one_min_ago = datetime.datetime.now() - datetime.timedelta(minutes=1)
            recent_traffic = df_logs[df_logs['timestamp'] > one_min_ago]
            if not recent_traffic.empty:
                recent_bytes = recent_traffic['sentbyte'].sum() + recent_traffic['rcvdbyte'].sum()
                stats["throughput_kbps"] = round((recent_bytes * 8) / (60 * 1024), 2)

            # Bandwidth Trend (Last 10 minutes)
            ten_min_ago = datetime.datetime.now() - datetime.timedelta(minutes=10)
            df_trend = df_logs[df_logs['timestamp'] > ten_min_ago].copy()
            if not df_trend.empty:
                df_trend['min'] = df_trend['timestamp'].dt.floor('min')
                trend = df_trend.groupby('min').apply(lambda x: (x['sentbyte'].sum() + x['rcvdbyte'].sum()) * 8 / (60 * 1024)).reset_index(name='kbps')
                stats["bandwidth_trend"] = trend
            else:
                stats["bandwidth_trend"] = pd.DataFrame(columns=['min', 'kbps'])

            stats["cpu_usage"] = min(95, 12 + (stats["throughput_kbps"] / 100))
            stats["ram_usage"] = min(90, 34 + (len(df_alerts) / 50))

        if not df_alerts.empty:
            stats["total_alerts"] = len(df_alerts)

    finally:
        conn.close()
    return df_logs, df_alerts, stats

try:
    df_logs, df_alerts, dash_stats = get_dashboard_data()
except Exception as e:
    st.error(f"DB Error: {e}")
    st.stop()

# --- 4. LAYOUT BUILDER ---

# Title
st.markdown('<div class="top-header">Forloggen</div>', unsafe_allow_html=True)

# Helper function to get Chart HTML
def get_chart_html(fig):
    # Generates a div-less HTML snippet for the plot
    html = fig.to_html(include_plotlyjs='cdn', full_html=False, config={'displayModeBar': False})
    # We need to strip the outer <div> wrapper plotly adds if we want full control, 
    # but usually it's fine. We need to ensure it fits our container.
    return html

# --- 5. STATE MANAGEMENT for NAVIGATION ---
if 'page' not in st.session_state:
    st.session_state.page = "Security Fabric"

def set_page(page_name):
    st.session_state.page = page_name

# --- 6. SIDEBAR NAVIGATION ---
with st.sidebar:
    st.markdown(f"### FORLOGGEN")
    st.caption(f"User: {st.session_state.username} | Role: {st.session_state.user_role.upper()}")
    
    if st.button("Logout", key="logout_btn", use_container_width=True):
        controller.remove("forloggen_user")
        st.session_state.logged_in = False
        st.session_state.user_role = None
        st.session_state.username = None
        st.session_state.user_id = None
        st.rerun()

    st.markdown("---")
    
    # Navigation styling helper
    def nav_button(label, page_name, active=False):
        bg = "#e84118" if active else "transparent"
        text = "white"
        # We use a native streamlit button, but we might lose the exact custom HTML styling 
        # unless we get creative. To keep it simple and functional while looking close:
        if st.button(label, key=label, use_container_width=True, type="primary" if active else "secondary"):
            set_page(page_name)
            st.rerun()

    # Define Routes based on User Scope
    current = st.session_state.page
    
    # Mapping new names to the requirements
    nav_button("Security Fabric", "Security Fabric", active=(current == "Security Fabric")) # Was 'Dashboard'
    nav_button("Network Defense", "Network Defense", active=(current == "Network Defense")) # Was 'Status' (The Anomaly View)
    nav_button("Traffic Analysis", "Traffic Analysis", active=(current == "Traffic Analysis")) # Was 'Policy' (Baseline Stats)
    nav_button("Rule Tuning", "Rule Tuning", active=(current == "Rule Tuning"))
    nav_button("Threat Reports", "Threat Reports", active=(current == "Threat Reports"))
    
    # SIMULATOR CONTROL (Production Level Integration)
    if st.session_state.user_role == 'admin':
        st.markdown("---")
        st.caption("Admin Controls")
        nav_button("Team Management", "Team Management", active=(current == "Team Management"))
        
    st.markdown("---")


    # SIMULATOR CONTROL (Production Level Integration)
    st.markdown("---")
    st.caption("Standard Simulator")
    clear_on_bulk = st.checkbox("Clear DB before bulk run", value=False)
    if st.button("RUN BULK SIMULATOR", use_container_width=True):
        import subprocess
        try:
            if clear_on_bulk:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("DELETE FROM alerts")
                cursor.execute("DELETE FROM logs")
                conn.commit()
                cursor.close()
                conn.close()

            with st.status("Simulating Bulk Traffic...", expanded=True) as status:
                st.write("Generating Noise & Attacks...")
                gen = subprocess.run(["python", "traffic_generator.py"], capture_output=True, text=True)
                if gen.returncode != 0:
                    st.error(f"Generator Error: {gen.stderr}")
                    status.update(label="Generation Failed", state="error")
                else:
                    st.write("Ingesting to Database...")
                    ingest = subprocess.run(["python", "ingest_logs.py"], capture_output=True, text=True)
                    if ingest.returncode != 0:
                        st.error(f"Ingestor Error: {ingest.stderr}")
                        status.update(label="Ingestion Failed", state="error")
                    else:
                        st.write(f"Done: {ingest.stdout.strip()}")
                        status.update(label="Simulation Complete!", state="complete", expanded=False)
                        st.toast("Updated with fresh data!")
                        st.cache_data.clear() # FORCE cache clear before re-fetching
                        st.session_state.page = st.session_state.page # Explicitly preserve current page
                        time.sleep(0.5)
                        st.rerun()
        except Exception as e:
            st.error(f"Critical Simulator Error: {e}")

    st.markdown("---")
    st.caption("Advanced Precision Simulator")
    with st.expander("Granular Controls", expanded=False):
        b_count = st.number_input("Baseline Logs", 0, 10000, 10)
        s_count = st.number_input("SSH Attacks", 0, 1000, 0)
        d_count = st.number_input("DNS Attacks", 0, 1000, 0)
        bc_count = st.number_input("Beacons", 0, 1000, 0)
        clear_on_prec = st.checkbox("Clear DB before injection", value=True)
        
        if st.button("INJECT PRECISION TRAFFIC", use_container_width=True):
            import subprocess
            try:
                if clear_on_prec:
                    conn = get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM alerts")
                    cursor.execute("DELETE FROM logs")
                    conn.commit()
                    cursor.close()
                    conn.close()

                with st.status("Injecting Specific Traffic...", expanded=True) as status:
                    cmd = ["python", "traffic_generator.py", 
                           "--baseline", str(b_count),
                           "--ssh", str(s_count),
                           "--dns", str(d_count),
                           "--beacon", str(bc_count)]
                    
                    st.write(f"Executing: {' '.join(cmd)}")
                    gen = subprocess.run(cmd, capture_output=True, text=True)
                    
                    if gen.returncode != 0:
                        st.error(f"Generator Error: {gen.stderr}")
                        status.update(label="Injection Failed", state="error")
                    else:
                        st.write("Ingesting to Database...")
                        ingest = subprocess.run(["python", "ingest_logs.py"], capture_output=True, text=True)
                        if ingest.returncode != 0:
                            st.error(f"Ingestor Error: {ingest.stderr}")
                            status.update(label="Ingestion Failed", state="error")
                        else:
                            status.update(label=f"Injected {b_count+s_count+d_count+bc_count} logs", state="complete", expanded=False)
                            st.toast("Precision injection complete!")
                            st.cache_data.clear()
                            time.sleep(0.5)
                            st.rerun()
            except Exception as e:
                st.error(f"Simulator Error: {e}")

    if st.button("CLEAR ALL DATA", use_container_width=True):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM alerts")
        cursor.execute("DELETE FROM logs")
        conn.commit()
        cursor.close()
        conn.close()
        st.toast("Database Cleared")
        st.rerun()


# --- 7. ROUTE: SECURITY FABRIC (Overview) ---
if st.session_state.page == "Security Fabric":
    
    # Title
    st.markdown('<div class="top-header">Security Fabric Overview</div>', unsafe_allow_html=True)

    # Style the monitoring section as a clean light area
    st.markdown("""
        <style>
        .monitoring-ctrl-row {
            background-color: #f1f3f5;
            padding: 15px;
            border-radius: 6px 6px 0 0;
            margin-bottom: 0px;
            display: flex;
            align-items: center;
            border: 1px solid #d0d7de;
            border-bottom: none;
        }
        .monitoring-ctrl-row .sub-header {
            color: #24292f !important;
            margin: 0 !important;
        }
        /* Specific override for fabric controls */
        .fabric-ctrl-container .stButton>button {
            background-color: #ffffff !important;
            color: #24292f !important;
            border: 1px solid #d0d7de !important;
            box-shadow: 0 1px 2px rgba(27,31,35,0.04) !important;
        }
        .fabric-ctrl-container .stButton>button:hover {
            background-color: #f6f8fa !important;
            border-color: #afb8c1 !important;
        }
        .fabric-ctrl-container .stButton>button p {
            color: #24292f !important;
        }
        </style>
    """, unsafe_allow_html=True)

    # ROW 1: Control Row (Dark Console Style)
    with st.container():
        st.markdown('<div class="fabric-ctrl-container">', unsafe_allow_html=True)
        st.markdown('<div class="monitoring-ctrl-row">', unsafe_allow_html=True)
        col_h, col_b1, col_b2 = st.columns([1.5, 1, 1])
        with col_h:
            st.markdown('<div class="sub-header" style="color: #24292f !important; font-size: 16px; font-weight: 600;">REAL-TIME FABRIC MONITORING</div>', unsafe_allow_html=True)
        with col_b1:
            if st.button("Clear Fabric History", use_container_width=True, key="fab_btn_clear"):
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("DELETE FROM alerts")
                cursor.execute("DELETE FROM logs")
                conn.commit()
                cursor.close()
                conn.close()
                st.cache_data.clear()
                st.toast("Database Cleared")
                st.rerun()
        with col_b2:
            if st.button("Refresh Telemetry", use_container_width=True, key="fab_btn_refresh"):
                st.cache_data.clear()
                st.rerun()
        st.markdown('</div></div>', unsafe_allow_html=True)

    live_col1, live_col2 = st.columns([2, 1])
    with live_col2:
        # Dynamic Security Level Logic
        alert_count = len(df_alerts)
        if alert_count > 50:
            sec_label, sec_color, sec_bg = "CRITICAL", "#cf222e", "#ffebe9"
        elif alert_count > 10:
            sec_label, sec_color, sec_bg = "ELEVATED", "#9a6700", "#fff8c5"
        else:
            sec_label, sec_color, sec_bg = "LOW", "#1a7f37", "#dafbe1"

        alert_entries_html = ""
        if not df_alerts.empty:
            for _, row in df_alerts.head(15).iterrows():
                ts = str(row['timestamp']).split('.')[0]
                risk_style = "color: #cf222e; font-weight: bold;" if "critical" in str(row.get('comments', '')).lower() or "tunneling" in row['detection_type'].lower() else "color: #9a6700; font-weight: bold;"
                
                alert_entries_html += f'<div style="margin-bottom: 8px; border-left: 2px solid #d0d7de; padding-left: 10px; font-family: monospace;"><div style="font-size: 10px; color: #57606a;">[{ts}]</div><div style="font-size: 11px;"><span style="{risk_style}">{row["detection_type"].upper()}</span></div><div style="font-size: 10px; color: #24292f;">SRC: <span style="color: #0969da;">{row["src_ip"]}</span> | <span style="font-style: italic;">{row.get("mitre_technique", "N/A")}</span></div></div>'
        else:
            alert_entries_html = '<div class="terminal-text" style="text-align: center; margin-top: 100px; opacity: 0.5;">NO THREATS DETECTED</div>'

        st.markdown(f"""
<div class="dashboard-card" style="height: 350px; background-color: #ffffff; border: 1px solid #d0d7de; border-top: 3px solid {sec_color}; padding: 0px; overflow: hidden; border-radius: 6px;">
    <div style="background: {sec_bg}; padding: 8px 15px; color: {sec_color} !important; font-family: monospace; font-size: 11px; display: flex; justify-content: space-between; border-bottom: 1px solid #d0d7de;">
        <span style="color: {sec_color} !important;">>_ ALERT_TELEMETRY</span>
        <span style="color: {sec_color}; font-weight:bold;">SEC_LEVEL: {sec_label}</span>
    </div>
    <div style="height: 310px; overflow-y: auto; padding: 15px; font-family: 'Consolas', 'Monaco', monospace; font-size: 11px; color: #24292f; line-height: 1.4;">
{alert_entries_html}
    </div>
</div>
""", unsafe_allow_html=True)
    with live_col1:
        log_entries_html = ""
        if not df_logs.empty:
            for _, row in df_logs.head(20).iterrows():
                ts = str(row['timestamp']).split('.')[0]
                action_style = "color: #cf222e !important; font-weight: bold;" if row['action'] == 'deny' else "color: #1a7f37 !important; font-weight: bold;"
                
                log_entries_html += f'<div style="margin-bottom: 4px; border-left: 2px solid #d0d7de; padding-left: 10px; font-family: monospace;"><span style="color:#57606a;">[{ts}]</span> <span style="color:#24292f;">{row["protocol"]}</span> <span style="color:#0969da;">{row["src_ip"]}</span> <span style="color:#57606a;">→</span> <span style="color:#0969da;">{row["dst_ip"]}</span> <span style="{action_style}">[{row["action"].upper()}]</span></div>'
        else:
            log_entries_html = '<div class="terminal-text" style="text-align: center; margin-top: 100px; opacity: 0.5;">WAITING FOR TELEMETRY DATA...</div>'

        st.markdown(f"""
<div class="dashboard-card" style="height: 350px; background-color: #ffffff; border: 1px solid #d0d7de; border-top: 3px solid #0969da; padding: 0px; overflow: hidden; border-radius: 6px;">
    <div style="background: #f6f8fa; padding: 8px 15px; color: #57606a !important; font-family: monospace; font-size: 11px; display: flex; justify-content: space-between; border-bottom: 1px solid #d0d7de;">
        <span style="color: #57606a !important;">>_ LIVE_LOG_STREAM</span>
        <span style="color: #1a7f37; font-weight:bold;">LIVE</span>
    </div>
    <div style="height: 310px; overflow-y: auto; padding: 15px; font-family: 'Consolas', 'Monaco', monospace; font-size: 11px; color: #24292f; line-height: 1.6;">
{log_entries_html}
    </div>
</div>
""", unsafe_allow_html=True)
    # --- DASHBOARD BOTTOM: THREAT INVENTORY ---
    st.markdown('<div class="module-header"><span>Security Threat Inventory</span><span class="status-pill status-crit">CRITICAL EVENTS</span></div>', unsafe_allow_html=True)
    
    if not df_alerts.empty:
        # Standardize threat inventory columns
        threat_df = df_alerts[['timestamp', 'src_ip', 'detection_type', 'mitre_technique']].head(20).copy()
        threat_df['timestamp'] = pd.to_datetime(threat_df['timestamp']).dt.strftime('%H:%M:%S')
        
        def color_threat(val):
            color = '#cf222e' if 'tunneling' in str(val).lower() else '#9a6700'
            return f'color: {color}; font-weight: bold;'
        
        st.dataframe(
            threat_df.style.applymap(color_threat, subset=['detection_type']).set_properties(**{
                'color': '#24292f', 
                'background-color': '#ffffff',
                'font-family': 'monospace',
                'font-size': '11px'
            }),
            use_container_width=True,
            hide_index=True
        )
    else:
        st.markdown('<div class="dashboard-module module-sharp" style="text-align:center; padding:40px;">[CLEANSET] No active threats in inventory.</div>', unsafe_allow_html=True)

    # ROW 2: System Info | Engine Stats | Suspicious Activity
    col1, col2, col3 = st.columns(3)

    if not df_logs.empty:
        first_log_time = pd.to_datetime(df_logs['timestamp']).min()
        uptime_delta = datetime.datetime.now() - first_log_time
        uptime_str = str(uptime_delta).split('.')[0]
    else:
        uptime_str = "0:00:00"

    with col1:
        st.markdown(f"""
        <div class="dashboard-module module-soft">
            <div class="module-header">SYSTEM INFORMATION</div>
            <div class="data-row"><span class="data-label">Host</span><span class="data-val">SOC_ENGINE_ALPHA</span></div>
            <div class="data-row"><span class="data-label">SN</span><span class="data-val">FGT60F-SIM-5521</span></div>
            <div class="data-row"><span class="data-label">CPU/RAM</span><span class="data-val">{dash_stats.get('cpu_usage', 0):.1f}% / {dash_stats.get('ram_usage', 0):.1f}%</span></div>
            <div class="data-row"><span class="data-label">Sessions</span><span class="data-val">{dash_stats.get('active_sessions', 0)}</span></div>
            <div class="data-row"><span class="data-label">Uptime</span><span class="data-val">{uptime_str}</span></div>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="dashboard-module module-soft">
            <div class="module-header">SECURITY ENGINE STATS</div>
            <div class="data-row"><span class="data-label">Throughput</span><span class="data-val">{dash_stats.get('throughput_kbps', 0):.1f} Kbps</span></div>
            <div class="data-row"><span class="data-label">Processed</span><span class="data-val">{(dash_stats.get('total_bytes', 0)/1024/1024):.2f} MB</span></div>
            <div class="data-row"><span class="data-label">Active Users</span><span class="data-val">{dash_stats.get('active_users', 0)}</span></div>
            <div class="data-row"><span class="data-label">Policies</span><span class="data-val">{dash_stats.get('active_policies', 0)}</span></div>
            <div class="data-row"><span class="data-label">IPS Engine</span><span class="data-val" style="color:#238636;">ACTIVE</span></div>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        if not df_alerts.empty:
            ssh_attacks = len(df_alerts[df_alerts['detection_type'].str.contains('SSH', case=False)])
            dns_tunnels = len(df_alerts[df_alerts['detection_type'].str.contains('DNS', case=False)])
            blocked_ips = df_alerts['src_ip'].nunique()
        else:
            ssh_attacks = 0; dns_tunnels = 0; blocked_ips = 0

        st.markdown(f"""
        <div class="dashboard-module module-soft">
            <div class="module-header">SUSPICIOUS ACTIVITY</div>
            <div class="data-row"><span class="data-label">SSH Brute Force</span><span class="data-val" style="color:#f85149;">{ssh_attacks}</span></div>
            <div class="data-row"><span class="data-label">DNS Tunneling</span><span class="data-val" style="color:#f85149;">{dns_tunnels}</span></div>
            <div class="data-row"><span class="data-label">Unique Sources</span><span class="data-val">{blocked_ips}</span></div>
            <div class="data-row" style="border-top: 1px solid #30363d; margin-top:5px; padding-top:8px;">
                <span class="data-label" style="font-weight:bold;">TOTAL THREATS</span>
                <span class="data-val" style="color:#f85149; font-size:14px;">{len(df_alerts)}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # End of Security Fabric Page

# --- 8. ROUTE: NETWORK DEFENSE (Attack Details) ---
elif st.session_state.page == "Network Defense":
    st.markdown('<div class="top-header">Network Defense: Anomaly Detection</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    # 1. IoT SSH Abuse
    with col1:
        ssh_logs = df_logs[df_logs['protocol'].str.lower() == 'ssh'] if not df_logs.empty and 'protocol' in df_logs.columns else pd.DataFrame()
        ssh_alerts = df_alerts[df_alerts['detection_type'].str.contains('SSH', case=False)] if not df_alerts.empty else pd.DataFrame()
        
        if not ssh_logs.empty:
            ssh_logs['time'] = pd.to_datetime(ssh_logs['timestamp'])
            counts = ssh_logs.groupby(ssh_logs['time'].dt.floor('T')).size().reset_index(name='events')
            fig_ssh = px.area(counts, x='time', y='events')
            fig_ssh.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color="#57606a", size=10), height=200, margin=dict(l=0, r=0, t=10, b=0))
            fig_ssh.update_traces(line_color='#0969da', fillcolor='rgba(9, 105, 218, 0.05)')
            chart_html = get_chart_html(fig_ssh)
        else:
            chart_html = '<div style="color:#484f58; padding:20px; text-align:center; font-size:12px;">NO SSH EVENT DATA</div>'

        st.markdown(f"""
        <div class="dashboard-module module-sharp" style="min-height: 480px;">
            <div class="module-header"><span>IOT / SSH BRUTE FORCE</span><span class="status-pill status-warn">HEURISTIC</span></div>
            <div class="data-row"><span class="data-label">Mitre Tactic</span><span class="data-val">Credential Access (TA0006)</span></div>
            <div class="data-row"><span class="data-label">Total Events</span><span class="data-val">{len(ssh_logs)}</span></div>
            <div class="data-row"><span class="data-label">Alert Count</span><span class="data-val" style="color:#cf222e;">{len(ssh_alerts)}</span></div>
            <div style="margin-top:15px; border: 1px solid #d0d7de; background:#ffffff;">
                {chart_html}
            </div>
        </div>
        """, unsafe_allow_html=True)

    # 2. DNS Tunneling
    with col1:
        dns_alerts = df_alerts[df_alerts['detection_type'] == 'DNS Tunneling'] if not df_alerts.empty else pd.DataFrame()
        st.markdown(f"""
        <div class="dashboard-module module-sharp">
            <div class="module-header"><span>DNS TUNNELING PIPELINE</span><span class="status-pill status-crit">CRITICAL</span></div>
            <div class="data-row"><span class="data-label">Mitre Tactic</span><span class="data-val">Command and Control (TA0011)</span></div>
            <div class="data-row"><span class="data-label">Technique</span><span class="data-val">App Layer: DNS (T1071.004)</span></div>
            <div class="data-row"><span class="data-label">Active Alerts</span><span class="data-val" style="color:#cf222e;">{len(dns_alerts)}</span></div>
            <div style="font-size: 11px; font-weight: 600; margin-top: 15px; margin-bottom: 5px; color:#57606a;">LOG ANOMALY EXTRACTS</div>
        </div>
        """, unsafe_allow_html=True)
        
        if not dns_alerts.empty:
            st.dataframe(
                dns_alerts[['timestamp', 'src_ip', 'mitre_technique']].head(5).style.set_properties(**{'font-family': 'monospace', 'font-size': '11px'}),
                hide_index=True, use_container_width=True
            )
        else:
            st.markdown('<div class="terminal-mono" style="padding:10px; color:#484f58;">[EMPTYSET] No DNS anomalies detected.</div>', unsafe_allow_html=True)
            
        st.markdown("</div>", unsafe_allow_html=True)

    # 3. Attacked Asset Breakdown
    with col2:
        if not df_alerts.empty:
            attacked_assets = df_alerts.groupby('src_ip').size().reset_index(name='alert_count').sort_values('alert_count', ascending=False)
            fig_assets = px.bar(attacked_assets.head(5), x='src_ip', y='alert_count', color_discrete_sequence=['#cf222e'])
            fig_assets.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color="#57606a", size=10), height=300, margin=dict(t=10, b=0, l=0, r=0))
            asset_chart_html = get_chart_html(fig_assets)
            
            st.markdown(f"""
            <div class="dashboard-module module-round" style="min-height: 480px;">
                <div class="module-header"><span>TOP TARGETED ASSETS</span></div>
                <div style="font-size: 12px; color:#57606a; margin-bottom: 10px;">Internal hosts with maximal threat exposure score.</div>
                <div style="border: 1px solid #d0d7de; background:#ffffff;">
                    {asset_chart_html}
                </div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("Insufficient telemetry for asset breakdown.")

# --- 10. ROUTE: RULE TUNING ---
elif st.session_state.page == "Rule Tuning":
    st.markdown('<div class="top-header">Rule Sensitivity Tuning</div>', unsafe_allow_html=True)
    st.markdown('<div class="terminal-mono" style="color:#57606a; margin-bottom:20px;">[CONFIG_ENGINE] Adjust detection heuristics for real-time log analysis.</div>', unsafe_allow_html=True)

    # Load current config
    import json
    config_path = "config.json"
    try:
        with open(config_path, 'r') as f:
            full_config = json.load(f)
    except Exception:
        full_config = {"detection_rules": {}}
    
    rules = full_config.get('detection_rules', {})

    col1, col2 = st.columns(2)

    with col1:
        st.markdown('<div class="dashboard-module module-soft"><div class="module-header">SSH DETECTION LOGIC</div>', unsafe_allow_html=True)
        check_iot = st.toggle("IOT_DEVICE_IDENT", value=rules.get('ssh', {}).get('check_iot_types', True))
        fail_check = st.toggle("AUTH_FAIL_ALERT", value=rules.get('ssh', {}).get('fail_threshold_enabled', True))
        st.markdown('</div>', unsafe_allow_html=True)
        
    with col2:
        st.markdown('<div class="dashboard-module module-soft"><div class="module-header">DNS TUNNELING PARAMETERS</div>', unsafe_allow_html=True)
        entropy = st.slider("ENTROPY_THRESHOLD", 3.0, 7.0, float(rules.get('dns', {}).get('entropy_threshold', 4.5)), 0.1)
        max_len = st.slider("MAX_SUBDOMAIN_LEN", 20, 100, int(rules.get('dns', {}).get('max_length', 50)))
        vol_thr = st.slider("VOLUME_LIMIT", 5, 50, int(rules.get('dns', {}).get('volume_threshold', 10)))
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("---")
    c1, c2 = st.columns(2)
    with c1:
        if st.button("SAVE_CONFIG", type="primary", use_container_width=True):
            full_config['detection_rules'] = {
                "ssh": {"check_iot_types": check_iot, "fail_threshold_enabled": fail_check},
                "dns": {"entropy_threshold": entropy, "max_length": max_len, "volume_threshold": vol_thr}
            }
            with open(config_path, 'w') as f:
                json.dump(full_config, f, indent=2)
            st.success("CONFIGURATION_COMMIT_SUCCESS")
            time.sleep(1)
            st.rerun()

    with c2:
        if st.button("RESTORE_DEFAULTS", use_container_width=True):
             full_config['detection_rules'] = {
                "ssh": {"check_iot_types": True, "fail_threshold_enabled": True},
                "dns": {"entropy_threshold": 4.5, "max_length": 50, "volume_threshold": 10}
            }
             with open(config_path, 'w') as f:
                json.dump(full_config, f, indent=2)
             st.info("FACTORY_RESET_COMPLETE")
             time.sleep(1)
             st.rerun()


# --- 9. ROUTE: TRAFFIC ANALYSIS (Baseline) ---
elif st.session_state.page == "Traffic Analysis":
    st.markdown('<div class="top-header">Traffic Analysis: Baseline</div>', unsafe_allow_html=True)
    
    if not df_logs.empty:
        # 1. Top Metrics
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f'<div class="dashboard-module module-sharp"><div class="module-header">BANDWIDTH</div><div style="font-size:24px; font-weight:bold; color:#0969da;">{dash_stats.get("throughput_kbps", 0):.1f} <span style="font-size:12px;">Kbps</span></div></div>', unsafe_allow_html=True)
        with c2:
            st.markdown(f'<div class="dashboard-module module-sharp"><div class="module-header">TOTAL SESSIONS</div><div style="font-size:24px; font-weight:bold; color:#24292f;">{dash_stats.get("total_logs", 0):,}</div></div>', unsafe_allow_html=True)
        with c3:
            st.markdown(f'<div class="dashboard-module module-sharp"><div class="module-header">POLICY UTILIZATION</div><div style="font-size:24px; font-weight:bold; color:#1a7f37;">{dash_stats.get("active_policies", 0)} <span style="font-size:12px;">Rules active</span></div></div>', unsafe_allow_html=True)

        # 3. Raw Data
        st.markdown('<div class="module-header">DEEP PACKET INSPECTION (DPI) LOGS</div>', unsafe_allow_html=True)
        cols_to_show = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'action', 'sentbyte', 'rcvdbyte', 'policyid']
        available_cols = [c for c in cols_to_show if c in df_logs.columns]
        
        st.dataframe(
            df_logs[available_cols].head(100).style.set_properties(**{
                'font-family': 'monospace', 
                'font-size': '11px',
                'color': '#24292f',
                'background-color': '#ffffff'
            }),
            hide_index=True, use_container_width=True
        )
    else:
        st.info("No baseline traffic telemetry located.")

elif st.session_state.page == "Asset Inventory":
    st.markdown('<div class="top-header">Asset Inventory</div>', unsafe_allow_html=True)
    if not df_logs.empty:
        assets = df_logs.groupby(['src_ip', 'device_type']).size().reset_index(name='events')
        st.dataframe(
            assets.style.set_properties(**{
                'color': '#24292f',
                'background-color': '#ffffff'
            }),
            use_container_width=True, hide_index=True
        )
    else:
        st.info("No assets discovered.")

# --- 11. ROUTE: TEAM MANAGEMENT ---
elif st.session_state.page == "Team Management":
    st.markdown('<div class="top-header">Team Management</div>', unsafe_allow_html=True)
    if st.session_state.user_role != 'admin':
        st.error("Unauthorized: Admin Access Required")
    else:
        # Fetch Team
        team_members = AuthManager.get_team_members(st.session_state.user_id)
        
        # Summary Cards
        c1, c2 = st.columns(2)
        with c1:
            st.markdown(f"""
            <div class="dashboard-module module-soft">
                <div class="module-header">YOUR TEAM SIZE</div>
                <div style="font-size: 32px; font-weight: bold; color: #0969da;">{len(team_members)}</div>
                <div style="font-size: 11px; color: #57606a;">Active Analyst Accounts</div>
            </div>
            """, unsafe_allow_html=True)
        
        # New Analyst Form
        with c2:
            st.markdown('<div class="dashboard-module module-soft">', unsafe_allow_html=True)
            st.markdown('<div class="module-header">REGISTER NEW ANALYST</div>', unsafe_allow_html=True)
            with st.form("new_analyst"):
                new_user = st.text_input("Username")
                new_pass = st.text_input("Password", type="password")
                if st.form_submit_button("Create Account"):
                    if AuthManager.create_user(new_user, new_pass, 'user', managed_by=st.session_state.user_id):
                        st.success(f"Created analyst: {new_user}")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Failed. Username might be taken.")
            st.markdown('</div>', unsafe_allow_html=True)

        # List Team Members
        st.markdown("### Mapped Analysts")
        if team_members:
            for member in team_members:
                st.markdown(f"""
                <div style="padding: 10px; border-bottom: 1px solid #d0d7de; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-weight: bold; color: #24292f;">{member['username']}</span> 
                        <span class="status-pill status-ok">ACTIVE</span>
                    </div>
                    <div style="font-size: 11px; color: #57606a; font-family: monospace;">ID: {member['id']} | ROLE: {member['role'].upper()} | JOINED: {member['created_at']}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("You have no analysts assigned to your account.")

# --- 12. ROUTE: THREAT REPORTS ---
elif st.session_state.page == "Threat Reports":
    st.markdown('<div class="top-header">Threat Intelligence Reports</div>', unsafe_allow_html=True)
    
    # Refresh logic
    if st.button("Refresh Report Data"):
        st.cache_data.clear()
        st.rerun()

    # =========================
    # THREAT VISUAL ANALYTICS
    # =========================
    st.markdown("""
    <div class="dashboard-module module-soft">
        <div class="module-header">THREAT DISTRIBUTION OVERVIEW</div>
    """, unsafe_allow_html=True)

    if not df_alerts.empty:
        c1, c2 = st.columns([2, 1])
        with c1:
            threat_count = df_alerts['detection_type'].value_counts().reset_index()
            threat_count.columns = ["Threat Type", "Count"]

            # Professional Color Palette matching the theme
            custom_colors = ['#cf222e', '#d96c00', '#9a6700', '#0969da', '#57606a']
            
            fig = px.pie(
                threat_count,
                names="Threat Type",
                values="Count",
                title=None, 
                hole=0.6, 
                color_discrete_sequence=custom_colors
            )
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', 
                plot_bgcolor='rgba(0,0,0,0)',
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.2, xanchor="center", x=0.5),
                margin=dict(t=0, b=0, l=0, r=0),
                height=250
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with c2:
             st.markdown("#### Execution Summary")
             top_threat = threat_count.iloc[0]
             
             st.markdown(f"""
             <div style="background-color: #f6f8fa; padding: 15px; border-radius: 6px; border-left: 4px solid #cf222e;">
                <div style="color: #57606a; font-size: 11px; text-transform: uppercase; font-weight: 600;">Primary Vector</div>
                <div style="color: #24292f; font-size: 18px; font-weight: bold;">{top_threat['Threat Type']}</div>
                <div style="color: #cf222e; font-size: 24px; font-weight: bold; margin-top: 5px;">{top_threat['Count']} <span style="font-size:12px; color:#57606a;">Events</span></div>
             </div>
             
             <div style="margin-top: 10px; background-color: #f6f8fa; padding: 15px; border-radius: 6px; border-left: 4px solid #9a6700;">
                <div style="color: #57606a; font-size: 11px; text-transform: uppercase; font-weight: 600;">Active Campaign</div>
                <div style="color: #24292f; font-size: 14px; font-weight: 600;">APT-29 Simulation</div>
             </div>
             """, unsafe_allow_html=True)

    else:
        st.info("No threats detected yet.")
    st.markdown("</div>", unsafe_allow_html=True)


    # =========================
    # SEVERITY FILTER
    # =========================
    st.markdown("""
    <div class="dashboard-module module-sharp" style="margin-top: 20px;">
        <div class="module-header">FORENSIC ALERT FILTER</div>
    """, unsafe_allow_html=True)

    severity = st.selectbox("Select Severity Scope", ["All","Critical","High","Medium","Low"])

    if severity != "All":
        filtered_alerts = df_alerts[df_alerts["severity"].str.lower() == severity.lower()]
    else:
        filtered_alerts = df_alerts

    if not filtered_alerts.empty:
        # Clean Table Styling
        st.dataframe(
            filtered_alerts[['timestamp','src_ip','detection_type','severity','mitre_technique']].style.apply(
                lambda x: ['color: #cf222e; font-weight: bold;' if x.name == 'severity' and 'critical' in str(x.values).lower() else '' for i in x], axis=1
            ).set_properties(**{
                'font-family': 'monospace',
                'font-size': '11px', 
                'background-color': '#ffffff',
                'color': '#57606a'
            }),
            use_container_width=True,
            hide_index=True
        )
    else:
         st.markdown('<div style="padding: 20px; text-align: center; color: #57606a;">No alerts match this filter criteria.</div>', unsafe_allow_html=True)

    st.markdown("</div>", unsafe_allow_html=True)


    # =========================
    # MITRE SUMMARY
    # =========================
    st.markdown("""
    <div class="dashboard-module module-round" style="margin-top: 20px;">
        <div class="module-header">MITRE ATT&CK MATRIX MAPPING</div>
    """, unsafe_allow_html=True)

    if not df_alerts.empty:
        mitre_table = (
            df_alerts.groupby("mitre_technique")
            .size()
            .reset_index(name="Count")
            .sort_values(by="Count", ascending=False)
        )
        st.table(mitre_table)
    else:
        st.info("No MITRE mapped alerts yet.")
    st.markdown("</div>", unsafe_allow_html=True)

else:
    st.info("Module under development.")
