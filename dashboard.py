import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from api.db import get_db_connection
import datetime
import time
import warnings

# Use specific warning filter for the pandas SQL alchemy warning
warnings.filterwarnings('ignore', category=UserWarning, module='pandas')

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

# --- 2. CUSTOM CSS (MICROSOFT XDR STYLE) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Segoe+UI:wght@300;400;600&display=swap');

    /* Microsoft Office/Defender Primary Palette */
    :root {
        --ms-primary: #0078d4;
        --ms-bg-main: #faf9f8;
        --ms-bg-card: #ffffff;
        --ms-border: #edebe9;
        --ms-text-main: #323130;
        --ms-text-sec: #605e5c;
        --ms-neutral-light: #f3f2f1;
        --ms-red: #d13438;
        --ms-orange: #ca5010;
        --ms-green: #107c10;
    }

    /* Global Settings */
    .stApp {
        background-color: var(--ms-bg-main);
        color: var(--ms-text-main);
        font-family: 'Segoe UI', wf_segoe-ui_normal, helvetica, arial, sans-serif;
    }
    
    .block-container {
        padding: 2rem 2rem 1.5rem 2rem !important;
        max-width: 100%;
    }
    
    /* Typography */
    h1, h2, h3, h4, h5, h6 {
        color: var(--ms-text-main) !important;
        font-weight: 600 !important;
        margin-bottom: 0.8rem !important;
    }
    
    /* Sidebar: Microsoft Portal Look */
    [data-testid="stSidebar"] {
        background-color: var(--ms-bg-main);
        border-right: 1px solid var(--ms-border);
    }
    [data-testid="stSidebar"] * {
        color: var(--ms-text-main) !important;
    }
    
    /* The XDR Module Container */
    .dashboard-module {
        background-color: var(--ms-bg-card);
        border: 1px solid var(--ms-border);
        padding: 16px;
        margin-bottom: 16px;
        border-radius: 2px; /* Microsoft flat design */
        box-shadow: 0 1.6px 3.6px 0 rgba(0,0,0,0.132), 0 0.3px 0.9px 0 rgba(0,0,0,0.108);
    }

    .module-header {
        font-size: 14px;
        font-weight: 600;
        color: var(--ms-text-main);
        padding-bottom: 8px;
        margin-bottom: 12px;
        border-bottom: 1px solid var(--ms-border);
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    
    .data-row {
        display: flex;
        justify-content: space-between;
        font-size: 13px;
        padding: 6px 0;
        border-bottom: 1px solid var(--ms-neutral-light);
    }
    .data-label { color: var(--ms-text-sec); }
    .data-val { color: var(--ms-primary); font-weight: 500; }
    
    /* defender severity pills */
    .status-pill {
        padding: 2px 10px;
        font-size: 11px;
        font-weight: 600;
        border-radius: 2px;
    }
    .status-ok { background: #dff6dd; color: #107c10; border: 1px solid #107c10; }
    .status-warn { background: #fff4ce; color: #ca5010; border: 1px solid #ca5010; }
    .status-crit { background: #fde7e9; color: #d13438; border: 1px solid #d13438; }

    .top-header {
        font-size: 24px;
        color: var(--ms-text-main);
        font-weight: 400; /* Microsoft headers are often lighter weight at large sizes */
        margin-bottom: 20px;
        border-bottom: 1px solid var(--ms-border);
        padding-bottom: 10px;
    }

    .terminal-mono {
        font-family: 'Consolas', 'Monaco', monospace;
        font-size: 12px;
        color: var(--ms-text-sec);
        background: var(--ms-neutral-light);
        padding: 2px 4px;
        border-radius: 2px;
    }

    /* Primary Microsoft Button */
    button[data-testid="baseButton-primary"] {
        background-color: var(--ms-primary) !important;
        border: 1px solid var(--ms-primary) !important;
        color: #ffffff !important;
        border-radius: 2px !important;
    }
    button[data-testid="baseButton-primary"]:hover {
        background-color: #005a9e !important;
        border-color: #005a9e !important;
    }
    
    /* Secondary Button */
    button[data-testid="baseButton-secondary"] {
        background-color: #ffffff !important;
        color: var(--ms-text-main) !important;
        border: 1px solid #8a8886 !important;
        border-radius: 2px !important;
    }
    button[data-testid="baseButton-secondary"]:hover {
        background-color: var(--ms-neutral-light) !important;
        border-color: #605e5c !important;
    }

    /* Active Nav Item Indicator */
    .nav-active {
        border-left: 4px solid var(--ms-primary) !important;
        background-color: var(--ms-neutral-light) !important;
    }
</style>
""", unsafe_allow_html=True)

# --- 3. DATA FETCHING ---
# @st.cache_data(ttl=5) # REMOVED: Caching causes staleness issues with rapid generation
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
        # We use st.button but add a helper to simulate the Microsoft vertical accent
        # Actually, since we can't easily add classes to specific st.buttons,
        # we will use the 'primary' type for active buttons which we styled to look like Microsoft selection.
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
        st.markdown("**Attack Vectors**")
        s_count = st.number_input("SSH Attacks", 0, 1000, 0)
        d_count = st.number_input("DNS Attacks", 0, 1000, 0)
        bc_count = st.number_input("Beacons", 0, 1000, 0)
        
        st.markdown("**Normal Baseline**")
        b_count = st.number_input("Mixed Standard (Legacy)", 0, 10000, 0)
        http_count = st.number_input("Normal Web Browsing (HTTP/S)", 0, 10000, 10)
        dns_norm_count = st.number_input("Normal DNS Queries", 0, 10000, 0)
        ssh_norm_count = st.number_input("Normal SSH Admin", 0, 10000, 0)
        
        st.markdown("**Timing**")
        offset_mins = st.number_input("Time Offset (minutes ago)", 0, 10000, 0, help="Shift the entire simulation window into the past.")
        
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
                           "--beacon", str(bc_count),
                           "--http", str(http_count),
                           "--dns_normal", str(dns_norm_count),
                           "--ssh_normal", str(ssh_norm_count),
                           "--offset", str(offset_mins)]
                    
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
                # Microsoft XDR color logic
                sev_color = "#d13438" if "critical" in str(row.get('severity', '')).lower() or "tunneling" in row['detection_type'].lower() else "#ca5010"
                
                alert_entries_html += f'<div style="margin-bottom: 12px; border-left: 3px solid {sev_color}; padding-left: 12px;"><div style="font-size: 11px; color: #605e5c;">{ts}</div><div style="font-size: 13px; font-weight: 600; color: #323130;">{row["detection_type"]}</div><div style="font-size: 11px; color: #605e5c;">{row["src_ip"]} | {row.get("mitre_technique", "N/A")}</div></div>'
        else:
            alert_entries_html = '<div class="terminal-text" style="text-align: center; margin-top: 100px; opacity: 0.5;">NO THREATS DETECTED</div>'

        st.markdown(f"""
<div class="dashboard-module" style="height: 350px; border-top: 4px solid {sec_color}; padding: 0px; overflow: hidden;">
    <div style="background: #ffffff; padding: 10px 16px; color: #323130; font-size: 14px; font-weight: 600; border-bottom: 1px solid #edebe9; display: flex; justify-content: space-between;">
        <span>Alerts and incidents</span>
        <span style="color: {sec_color}; font-size: 11px;">{sec_label}</span>
    </div>
    <div style="height: 310px; overflow-y: auto; padding: 16px;">
{alert_entries_html}
    </div>
</div>
""", unsafe_allow_html=True)
    with live_col1:
        # Download Controls
        if not df_logs.empty:
            d_col1, d_col2, d_col3 = st.columns([1, 1, 4])
            csv_data = df_logs.to_csv(index=False).encode('utf-8')
            json_data = df_logs.to_json(orient="records", date_format="iso")
            
            with d_col1:
                st.download_button(
                    label="Download CSV",
                    data=csv_data,
                    file_name=f"log_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    key="dl_csv"
                )
            with d_col2:
                st.download_button(
                    label="Download JSON",
                    data=json_data,
                    file_name=f"log_export_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    key="dl_json"
                )

        log_entries_html = ""
        if not df_logs.empty:
            for _, row in df_logs.head(20).iterrows():
                ts = str(row['timestamp']).split('.')[0]
                action_style = "color: #cf222e !important; font-weight: bold;" if row['action'] == 'deny' else "color: #1a7f37 !important; font-weight: bold;"
                svc_display = f"{row['service']}({row['dst_port']})" if row['service'] else row['protocol']
                
                log_entries_html += f'<div style="margin-bottom: 4px; border-left: 2px solid #d0d7de; padding-left: 10px; font-family: monospace;"><span style="color:#57606a;">[{ts}]</span> <span style="color:#24292f;">{svc_display}</span> <span style="color:#0969da;">{row["src_ip"]}</span>:<span style="color:#57606a;">{row["src_port"]}</span> <span style="color:#57606a;">→</span> <span style="color:#0969da;">{row["dst_ip"]}</span> <span style="{action_style}">[{row["action"].upper()}]</span></div>'
        else:
            log_entries_html = '<div class="terminal-text" style="text-align: center; margin-top: 100px; opacity: 0.5;">WAITING FOR TELEMETRY DATA...</div>'

        st.markdown(f"""

<div class="dashboard-card" style="height: 350px; background-color: #ffffff; border: 1px solid #d0d7de; border-top: 3px solid #0969da; padding: 0px; overflow: hidden; border-radius: 6px;">
    <div style="background: #f6f8fa; padding: 8px 15px; color: #57606a !important; font-family: monospace; font-size: 11px; display: flex; justify-content: space-between; border-bottom: 1px solid #d0d7de;">
        <span style="color: #57606a !important;">LIVE LOGS (LATEST 20)</span>
        <span style="color: #1a7f37; font-weight:bold;">ACTIVE</span>
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

    # ROW 2: Suspicious Activity (Now standalone)
    if not df_alerts.empty:
        ssh_attacks = len(df_alerts[df_alerts['detection_type'].str.contains('SSH', case=False)])
        dns_tunnels = len(df_alerts[df_alerts['detection_type'].str.contains('DNS', case=False)])
        blocked_ips = df_alerts['src_ip'].nunique()
    else:
        ssh_attacks = 0; dns_tunnels = 0; blocked_ips = 0

    c1, c2, c3 = st.columns([1,1,2])
    with c1:
        st.metric("Total Threats", len(df_alerts), delta_color="inverse")
    with c2:
        st.metric("Unique Sources", blocked_ips, delta_color="inverse")
    
    st.markdown(f"""
    <div class="dashboard-module module-soft">
        <div class="module-header">OFFENSE SUMMARY</div>
        <div class="data-row"><span class="data-label">SSH Brute Force</span><span class="data-val" style="color:#f85149;">{ssh_attacks}</span></div>
        <div class="data-row"><span class="data-label">DNS Tunneling</span><span class="data-val" style="color:#f85149;">{dns_tunnels}</span></div>
    </div>
    """, unsafe_allow_html=True)

    # End of Security Fabric Page

# --- 8. ROUTE: NETWORK DEFENSE (Attack Details) ---
elif st.session_state.page == "Network Defense":
    st.markdown('<div class="top-header">Network Defense: Anomaly Detection</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    # 1. IoT SSH Abuse (Fetch dedicated attack logs)
    with col1:
        # Specialized Query for SSH Attack History
        conn = get_db_connection()
        ssh_logs = pd.read_sql("SELECT * FROM logs WHERE protocol = '6' AND (service = 'SSH' OR dst_port = 22) ORDER BY timestamp DESC LIMIT 2000", conn)
        conn.close()
        
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
        st.markdown('<div class="dashboard-module"><div class="module-header">SSH DETECTION LOGIC</div>', unsafe_allow_html=True)
        check_iot = st.toggle("Analyze IoT types", value=rules.get('ssh', {}).get('check_iot_types', True))
        fail_check = st.toggle("Alert on auth failure", value=rules.get('ssh', {}).get('fail_threshold_enabled', True))
        st.markdown('</div>', unsafe_allow_html=True)
        
    with col2:
        st.markdown('<div class="dashboard-module"><div class="module-header">DNS TUNNELING PARAMETERS</div>', unsafe_allow_html=True)
        entropy = st.slider("Entropy threshold", 3.0, 7.0, float(rules.get('dns', {}).get('entropy_threshold', 4.5)), 0.1)
        max_len = st.slider("Max subdomain length", 20, 100, int(rules.get('dns', {}).get('max_length', 50)))
        vol_thr = st.slider("Volume limits", 5, 50, int(rules.get('dns', {}).get('volume_threshold', 10)))
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
            st.markdown(f'<div class="dashboard-module"><div class="module-header">BANDWIDTH</div><div style="font-size:24px; font-weight:400; color:{dash_stats.get("throughput_kbps", 0) > 100 and "#d13438" or "#0078d4"};">{dash_stats.get("throughput_kbps", 0):.1f} <span style="font-size:14px; color:#605e5c;">Kbps</span></div></div>', unsafe_allow_html=True)
        with c2:
            st.markdown(f'<div class="dashboard-module"><div class="module-header">TOTAL SESSIONS</div><div style="font-size:24px; font-weight:400; color:#323130;">{dash_stats.get("total_logs", 0):,}</div></div>', unsafe_allow_html=True)
        with c3:
            st.markdown(f'<div class="dashboard-module"><div class="module-header">POLICY UTILIZATION</div><div style="font-size:24px; font-weight:400; color:#107c10;">{dash_stats.get("active_policies", 0)} <span style="font-size:14px; color:#605e5c;">Active rules</span></div></div>', unsafe_allow_html=True)

        # 3. Raw Data

        st.markdown('<div class="module-header">DEEP PACKET INSPECTION (DPI) LOGS</div>', unsafe_allow_html=True)
        
        # Prepare Alert Mapping
        if not df_alerts.empty:
            alert_map = df_alerts.set_index('raw_log_reference')['detection_type'].to_dict()
            df_logs['is_threat'] = df_logs['id'].map(alert_map).notna()
            df_logs['threat_name'] = df_logs['id'].map(alert_map).fillna('')
        else:
            df_logs['is_threat'] = False
            df_logs['threat_name'] = ''

        view_mode = st.radio("Log Format", ["Parsed Table", "Raw Fortigate (Key-Value)"], horizontal=True)
        
        if view_mode == "Parsed Table":
            cols_to_show = ['timestamp', 'src_ip', 'dst_ip', 'protocol', 'action', 'threat_name', 'policyid', 'dstdomain']
            available_cols = [c for c in cols_to_show if c in df_logs.columns]
            
            # Apply highlighting
            def highlight_threats(row):
                # We check 'threat_name' because 'is_threat' is not in the subset cols_to_show
                if row.get('threat_name'):
                    return ['background-color: #ffebe9; color: #cf222e; font-weight: bold'] * len(row)
                return [''] * len(row)

            st.dataframe(
                df_logs[available_cols].head(100).style.apply(highlight_threats, axis=1).format({'timestamp': lambda x: str(x).split(".")[0]}),
                hide_index=True, use_container_width=True
            )
        else:
            # Raw View with Highlighting
            raw_data = df_logs[['timestamp', 'raw_log', 'is_threat', 'threat_name']].head(50)
            
            st.markdown('<div class="terminal-container" style="font-family: monospace; font-size: 12px; background: #f6f8fa; padding: 10px; border: 1px solid #d0d7de; border-radius: 6px;">', unsafe_allow_html=True)
            for _, row in raw_data.iterrows():
                if row['is_threat']:
                    # Red highlight for threats
                    st.markdown(f'<div style="color: #cf222e; background-color: #ffebe9; padding: 2px 4px; margin-bottom: 2px; border-left: 3px solid #cf222e;">[ALERT: {row["threat_name"]}] {row["timestamp"]} {row["raw_log"]}</div>', unsafe_allow_html=True)
                else:
                    st.markdown(f'<div style="color: #24292f; margin-bottom: 2px; padding: 2px 4px;">{row["timestamp"]} {row["raw_log"]}</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info("No baseline traffic telemetry located.")

elif st.session_state.page == "Asset Inventory":
    st.markdown('<div class="top-header">Asset Inventory</div>', unsafe_allow_html=True)
    if not df_logs.empty:
        assets = df_logs.groupby(['src_ip', 'device_type']).size().reset_index(name='events')
        st.dataframe(
            assets.style.set_properties(**{
                'color': '#323130',
                'background-color': '#ffffff',
                'font-size': '13px'
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
            <div class="dashboard-module">
                <div class="module-header">YOUR TEAM SIZE</div>
                <div style="font-size: 32px; font-weight: 300; color: var(--ms-primary);">{len(team_members)}</div>
                <div style="font-size: 12px; color: var(--ms-text-sec);">Active analyst accounts</div>
            </div>
            """, unsafe_allow_html=True)
        
        # New Analyst Form
        with c2:
            st.markdown('<div class="dashboard-module">', unsafe_allow_html=True)
            st.markdown('<div class="module-header">REGISTER NEW ANALYST</div>', unsafe_allow_html=True)
            with st.form("new_analyst"):
                new_user = st.text_input("Username")
                new_pass = st.text_input("Password", type="password")
                if st.form_submit_button("Create Account", type="primary"):
                    if AuthManager.create_user(new_user, new_pass, 'user', managed_by=st.session_state.user_id):
                        st.success(f"Account created: {new_user}")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Operation failed. Username may be unavailable.")
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
    
    # Explicitly fetch fresh full alert history for reporting
    conn = get_db_connection()
    df_report_alerts = pd.read_sql("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
    conn.close()

    # Refresh logic
    if st.button("Refresh Report Data"):
        st.cache_data.clear()
        st.rerun()

    # =========================
    # THREAT VISUAL ANALYTICS
    # =========================
    st.markdown("""
    <div class="dashboard-module">
        <div class="module-header">THREAT DISTRIBUTION OVERVIEW</div>
    """, unsafe_allow_html=True)

    if not df_report_alerts.empty:
        c1, c2 = st.columns([2, 1])
        with c1:
            threat_count = df_report_alerts['detection_type'].value_counts().reset_index()
            threat_count.columns = ["Threat Type", "Count"]

            # Microsoft XDR standard high-visibility palette
            custom_colors = ['#0078d4', '#d13438', '#ca5010', '#107c10', '#605e5c']
            
            fig = px.pie(
                threat_count,
                names="Threat Type",
                values="Count",
                title=None, 
                hole=0.55, 
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
             st.markdown('<div style="font-size: 14px; font-weight: 600; margin-bottom: 15px;">Asset vulnerability summary</div>', unsafe_allow_html=True)
             top_threat = threat_count.iloc[0]
             
             st.markdown(f"""
             <div style="background-color: var(--ms-bg-main); padding: 15px; border-left: 4px solid var(--ms-red); margin-bottom: 10px;">
                <div style="color: var(--ms-text-sec); font-size: 11px; text-transform: uppercase; font-weight: 600;">Priority Vector</div>
                <div style="color: var(--ms-text-main); font-size: 16px; font-weight: 600;">{top_threat['Threat Type']}</div>
                <div style="color: var(--ms-red); font-size: 24px; font-weight: 300; margin-top: 5px;">{top_threat['Count']} <span style="font-size:12px; color:var(--ms-text-sec);">Incidents</span></div>
             </div>
             
             <div style="background-color: var(--ms-bg-main); padding: 15px; border-left: 4px solid var(--ms-orange);">
                <div style="color: var(--ms-text-sec); font-size: 11px; text-transform: uppercase; font-weight: 600;">Campaign Context</div>
                <div style="color: var(--ms-text-main); font-size: 14px; font-weight: 600;">Persistence simulation</div>
             </div>
             """, unsafe_allow_html=True)

    else:
        st.info("No threats detected yet.")
    st.markdown("</div>", unsafe_allow_html=True)


    # =========================
    # SEVERITY FILTER
    # =========================
    st.markdown("""
    <div class="dashboard-module" style="margin-top: 20px;">
        <div class="module-header">FORENSIC ALERT FILTER</div>
    """, unsafe_allow_html=True)

    severity = st.selectbox("Select Severity Scope", ["All","Critical","High","Medium","Low"])

    if severity != "All":
        filtered_alerts = df_report_alerts[df_report_alerts["severity"].str.lower() == severity.lower()]
    else:
        filtered_alerts = df_report_alerts

    if not filtered_alerts.empty:
        # Clean Table Styling
        st.dataframe(
            filtered_alerts[['timestamp','src_ip','detection_type','severity','mitre_technique']].style.apply(
                lambda x: ['color: var(--ms-red); font-weight: 600;' if x.name == 'severity' and 'critical' in str(x.values).lower() else '' for i in x], axis=1
            ).set_properties(**{
                'font-family': 'Segoe UI',
                'font-size': '13px', 
                'background-color': '#ffffff',
                'color': '#323130'
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
    <div class="dashboard-module" style="margin-top: 20px;">
        <div class="module-header">MITRE ATT&CK MATRIX MAPPING</div>
    """, unsafe_allow_html=True)

    if not df_report_alerts.empty:
        mitre_table = (
            df_report_alerts.groupby("mitre_technique")
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
