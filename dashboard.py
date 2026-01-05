import streamlit as st
import pandas as pd
import time
import subprocess
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
def get_dashboard_data(limit=5000):
    conn = get_db_connection()
    try:
        # Logs - Ensure we get the latest by both timestamp and chronological order
        df_logs = pd.read_sql(f"SELECT * FROM logs ORDER BY timestamp DESC, id DESC LIMIT {limit}", conn)
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
    limit = st.session_state.get("log_limit", 5000)
    df_logs, df_alerts, dash_stats = get_dashboard_data(limit=limit)
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

@st.dialog("Log Details", width="large")
def view_log_details(row_data):
    # row_data is a Series or Dict
    st.markdown(f"""
    <div style="font-size: 13px; font-family: 'Segoe UI', sans-serif;">
        <div style="margin-bottom: 20px; padding: 10px; background-color: #f3f2f1; border-radius: 4px;">
            <strong>Timestamp:</strong> {row_data.get('timestamp', 'N/A')} <br>
            <strong>Log ID:</strong> {row_data.get('id', 'N/A')}
        </div>
    """, unsafe_allow_html=True)
    
    # Grid Layout for key fields
    c1, c2 = st.columns(2)
    with c1:
        st.caption("SOURCE")
        st.markdown(f"**IP:** `{row_data.get('src_ip', 'N/A')}`")
        st.markdown(f"**Port:** {row_data.get('src_port', 'N/A')}")
        st.markdown(f"**Device:** {row_data.get('device_type', 'N/A')}")
        st.markdown(f"**User:** {row_data.get('user', 'N/A')}")
    with c2:
        st.caption("DESTINATION")
        st.markdown(f"**IP:** `{row_data.get('dst_ip', 'N/A')}`")
        st.markdown(f"**Port:** {row_data.get('dst_port', 'N/A')}")
        st.markdown(f"**Service:** {row_data.get('service', 'N/A')}")
        st.markdown(f"**Protocol:** {row_data.get('protocol_name', row_data.get('protocol', 'N/A'))}")

    st.markdown("---")
    
    # Threat / Security Info
    if row_data.get('is_threat'):
        st.error(f"⚠️ THREAT DETECTED: {row_data.get('threat_name', 'Unknown')}")
    
    if row_data.get('msg'):
        st.info(f"**Message:** {row_data['msg']}")
        
    st.markdown("### Raw Log Data")
    # Convert to clean dict excluding internal fields
    display_dict = {k:v for k,v in row_data.items() if k not in ['min', 'is_threat', 'protocol_name']}
    st.json(display_dict)
    
    st.markdown("</div>", unsafe_allow_html=True)


# --- 5. STATE MANAGEMENT for NAVIGATION ---
if 'page' not in st.session_state:
    st.session_state.page = "Dashboard"

def set_page(page_name):
    st.session_state.page = page_name

# --- 6. TOP NAVIGATION BAR (No Sidebar) ---
if st.session_state.logged_in:
    # Top Header Layout
    h1, h2, h3 = st.columns([2, 5, 2])
    
    with h1:
        st.markdown(f"### FORLOGGEN")
        
    with h3:
        # Profile Menu via Expander
        # Using an emoji or icon representation for the 'People Image'
        user_display = f"👤 {st.session_state.username}"
        with st.expander(user_display, expanded=False):
            st.caption(f"Role: {st.session_state.user_role.upper()}")
            st.markdown("---")
            
            # Common Nav
            if st.button("Dashboard", key="nav_dash", use_container_width=True):
                set_page("Dashboard")
                st.rerun()
                
            # Admin Nav
            if st.session_state.user_role == 'admin':
                if st.button("Team Management", key="nav_team", use_container_width=True):
                    set_page("Team Management")
                    st.rerun()
            
            st.markdown("---")
            
            # Sign Out
            if st.button("Sign Out", key="logout_top", type="primary", use_container_width=True):
                controller.remove("forloggen_user")
                st.session_state.logged_in = False
                st.session_state.user_role = None
                st.session_state.username = None
                st.session_state.user_id = None
                st.rerun()

    st.markdown("---")

# Note: st.sidebar removed as requested. Single page view default.
        


# --- 7. ROUTE: DASHBOARD (Formerly Security Fabric) ---
if st.session_state.page == "Dashboard":
    
    # Title
    st.markdown('<div class="top-header">Dashboard</div>', unsafe_allow_html=True)

    # --- ROW 1: TOP 50 THREATS ---
    # --- ROW 1: ATTACK CATALOG (Interactive) ---
    # --- CONFIGURATION: SINGLE COLUMN ATTACK SIMULATOR ---
    # --- PATTERN-BASED CONFIGURATOR ---
    st.caption("ATTACK PATTERN SIMULATOR")
    
    # 1. Recursive Pattern Discovery
    import os
    pattern_root = "tests/pattern"
    available_patterns = []
    
    if os.path.exists(pattern_root):
        for root, dirs, files in os.walk(pattern_root):
            for file in files:
                if file.endswith(('.yaml', '.yml')):
                    # Create relative path for display/selection
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, start=pattern_root)
                    # Normalize path separators for consistency
                    rel_path = rel_path.replace("\\", "/") 
                    available_patterns.append(rel_path)
    
    if not available_patterns:
        st.warning(f"No patterns found in '{pattern_root}'. Please create YAML definition files.")
    
    # 2. SELECTION UI
    st.markdown("""
    <div style="padding: 15px; background: white; border: 1px solid #d0d7de; border-radius: 6px; margin-bottom: 20px;">
    """, unsafe_allow_html=True)
    
    # Baseline Config Row
    bc1, bc2 = st.columns([1, 4])
    with bc1:
        use_baseline = st.toggle("Inject Baseline", value=True)
    with bc2:
        if use_baseline:
            base_count = st.number_input("Baseline Noise Count", 100, 10000, 500, label_visibility="collapsed")
        else:
            st.caption("Baseline traffic disabled")

    st.markdown("---")

    # Group patterns by folder
    pattern_groups = {}
    for p in available_patterns:
        folder = os.path.dirname(p)
        if not folder: folder = "Root"
        if folder not in pattern_groups: pattern_groups[folder] = []
        pattern_groups[folder].append(p)

    c1, c2, c3 = st.columns([3, 1, 1])
    
    selected_patterns = []
    
    with c1:
        st.markdown("**Select Attack Pattern(s)**")
        # Custom Nested Dropdown behavior via Expander
        with st.expander("Choose Patterns (Multi-Select)", expanded=False):
            # Iterate groups
            for folder, files in pattern_groups.items():
                st.markdown(f"**📂 {folder}**")
                for f in files:
                    # Key needs to be unique if same filename exists in diff folders
                    if st.checkbox(os.path.basename(f), key=f"pat_{f}"):
                        selected_patterns.append(f)
                        
        if len(selected_patterns) > 0:
             st.caption(f"{len(selected_patterns)} patterns selected")
        else:
             st.caption("No patterns selected")
    
    with c2:
        st.markdown("**Attack Events (Per Pattern)**")
        p_count = st.number_input("Events", min_value=1, max_value=10000, value=20, label_visibility="collapsed")
        
    with c3:
        st.markdown("&nbsp;") # Spacer
        if st.button("EXECUTE PATTERN", type="primary", use_container_width=True, disabled=not available_patterns):
            if not selected_patterns:
                st.error("Please select at least one pattern.")
            else:
                import subprocess
                
                with st.status(f"Executing {len(selected_patterns)} Patterns...", expanded=True):
                    
                    # 1. Generate Attacks
                    for idx, pat in enumerate(selected_patterns):
                        full_pattern_path = os.path.join(pattern_root, pat)
                        st.write(f"[{idx+1}/{len(selected_patterns)}] Generating {pat}...")
                        
                        cmd = ["python", "traffic_generator.py", "--pattern", full_pattern_path, "--count", str(p_count)]
                        subprocess.run(cmd, capture_output=True, text=True)
                    
                    # 2. Generate Baseline (Once per batch to avoid duplication? Or per pattern? 
                    # Request implies "inject baseline". Usually done once per simulation run.
                    # We will run it ONCE at the end of the batch if enabled.)
                    if use_baseline:
                         st.write(f"Injecting Global Baseline ({base_count} events)...")
                         # We call with baseline ONLY (no pattern), but wait, traffic_generator logic 
                         # defaults to 'run()' if no args.
                         # We need to explicitly trigger baseline generation without pattern 
                         # OR we can just piggyback on the last pattern call?
                         # Better: separate call for clarity.
                         cmd_base = ["python", "traffic_generator.py", "--baseline", str(base_count)]
                         subprocess.run(cmd_base, capture_output=True)
                    
                    st.write("Ingesting Telemetry...")
                    subprocess.run(["python", "ingest_logs.py"], capture_output=True)
                    
                    st.success("Simulation Complete!")
                    time.sleep(1)
                    st.cache_data.clear()
                    st.rerun()
    
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")

    # --- LIVE FEED (Telemetry Only - No Analytics/Maintenance Tabs) ---
    tf_c1, tf_c2 = st.columns([4, 1])
    with tf_c1:
        st.subheader("Live Telemetry")
    with tf_c2:
        if st.button("CLEAR LOGS", type="secondary", use_container_width=True):
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("DELETE FROM alerts")
            c.execute("DELETE FROM logs")
            conn.commit()
            conn.close()
            st.toast("Logs Cleared")
            st.cache_data.clear()
            st.rerun()
    
    # 1. DPI LOGS (Reusing existing logic)
    if not df_logs.empty:
        # Re-apply threat highlighting logic
        if not df_alerts.empty:
            alert_map = df_alerts.set_index('raw_log_reference')['detection_type'].to_dict()
            df_logs['is_threat'] = df_logs['id'].map(alert_map).notna()
            df_logs['threat_name'] = df_logs['id'].map(alert_map).fillna('')
        else:
             df_logs['is_threat'] = False
             df_logs['threat_name'] = ''

        # Map Protocol Number to Name (Common)
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        df_logs['protocol_name'] = df_logs['protocol'].map(proto_map).fillna(df_logs['protocol'])

        # Updated Columns as per request (Action, Threat Name, Policy ID removed)
        # Added 'msg' to show SIEM details if available, and 'threat_name' as 'Detected Vulnerability'
        cols_to_show = ['timestamp', 'src_ip', 'dst_ip', 'protocol_name', 'service', 'rcvdbyte', 'sentbyte', 'threat_name']
        
        # If 'msg' exists (from pattern generator), show it
        if 'msg' in df_logs.columns:
            cols_to_show.append('msg')

        available_cols = [c for c in cols_to_show if c in df_logs.columns]
        
        def highlight_threats(row):
                if row.get('is_threat'): # Logic kept for color, but column hidden
                    return ['background-color: #fde7e9; color: #d13438; font-weight: 600'] * len(row)
                return [''] * len(row)

        selection = st.dataframe(
            df_logs[available_cols].head(100).style.apply(highlight_threats, axis=1).format({'timestamp': lambda x: str(x).split(".")[0]}),
            hide_index=True, 
            use_container_width=True, 
            height=500,
            column_config={
                "threat_name": "Detected Vulnerability",
                "protocol_name": "Protocol",
                "msg": "Payload / Details"
            },
            on_select="rerun",
            selection_mode="single-row"
        )
        
        if len(selection.selection.rows) > 0:
            # Get the selected row index (integer position in the displayed dataframe)
            row_idx = selection.selection.rows[0]
            # Retrieve the actual data from the source dataframe
            # Note: df_logs[available_cols].head(100) was used to display
            # But we want full details, so we should grab from df_logs (the full one) based on the same index logic
            # Be careful if dataframe is sorted or filtered.
            selected_row = df_logs.iloc[row_idx]
            view_log_details(selected_row)
    else:
        st.info("No DPI logs available.")
        
    st.markdown("---")
    
    # 2. ALERTS FEED
    # Security Alerts Removed as per request

    
    # End of Dashboard Page




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


else:
    st.info("Module under development.")
