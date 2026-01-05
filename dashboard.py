
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random
import time
import subprocess
import json
from sqlalchemy import create_engine, text

# Database Connection (Using SQLAlchemy for Pandas compatibility)
from config import Config
DB_URL = f"mysql+mysqlconnector://{Config.DB_USER}:{Config.DB_PASSWORD}@{Config.DB_HOST}/{Config.DB_NAME}"
engine = create_engine(DB_URL)

def get_db_connection():
    # Helper to return engine for pandas
    return engine

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Network Defense Log Generator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- 2. CUSTOM CSS ---
st.markdown("""
<style>
    /* Global Settings */
    .stApp {
        background-color: #f6f8fa;
        font-family: 'Segoe UI', 'Roboto', sans-serif;
    }
    
    /* Remove Padding/Whitespace */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
    }

    /* Hide Sidebar Element to be safe */
    [data-testid="stSidebar"] {
        display: none;
    }

    /* Card Styling */
    .custom-card {
        background-color: #ffffff;
        border: 1px solid #d0d7de;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        margin-bottom: 20px;
    }

    .card-header {
        font-size: 16px;
        font-weight: 600;
        color: #24292f;
        margin-bottom: 15px;
        display: flex;
        align-items: center;
    }

    /* Header Styling */
    .main-header {
        display: flex;
        align-items: center;
        margin-bottom: 20px;
    }
    .header-icon {
        font-size: 24px;
        margin-right: 10px;
        color: #0969da;
    }
    .header-title {
        font-size: 20px;
        font-weight: 600;
        color: #24292f;
    }
    .header-nav {
        margin-left: 30px;
        font-size: 14px;
        color: #57606a;
    }
    .nav-item {
        margin-right: 20px;
        cursor: pointer;
        padding: 5px 10px;
        border-radius: 6px;
    }
    .nav-item.active {
        background-color: #ddf4ff;
        color: #0969da;
        font-weight: 600;
    }

    /* Form Elements */
    .stSlider > div {
        padding-top: 10px;
    }
    
    /* Table Styling */
    .styled-table {
        width: 100%;
        border-collapse: collapse;
        font-family: 'Segoe UI', sans-serif;
        font-size: 13px;
    }
    .styled-table thead tr {
        background-color: #f6f8fa;
        text-align: left;
        border-bottom: 1px solid #d0d7de;
    }
    .styled-table th {
        padding: 10px;
        font-weight: 600;
        color: #57606a;
    }
    .styled-table td {
        padding: 8px 10px;
        border-bottom: 1px solid #eaecef;
        color: #24292f;
    }
    
    .status-badge {
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: 600;
    }
    .badge-allow { background-color: #dafbe1; color: #1a7f37; }
    .badge-deny { background-color: #ffebe9; color: #cf222e; }

    /* Button Styling */
    div.stButton > button {
        border-radius: 6px;
        font-weight: 600;
    }
    button[data-testid="baseButton-primary"] {
        background-color: #0969da;
        border-color: #0969da;
    }
</style>
""", unsafe_allow_html=True)

# --- 3. HEADER UI ---
col_head, col_user = st.columns([4, 1])
with col_head:
    st.markdown("""
        <div class="main-header">
            <span class="header-icon">📑</span>
            <span class="header-title">Network Defense Log Generator</span>
        </div>
    """, unsafe_allow_html=True)

# --- 4. GENERATOR CONFIGURATION SECTION ---
st.markdown('<div class="custom-card">', unsafe_allow_html=True)

# We use columns to create the 4-panel layout: Settings | Categories | Baseline | Attacks
c1, c2, c3, c4 = st.columns([1, 1, 1, 1.2])

with c1:
    st.markdown('<div class="card-header">Log Settings</div>', unsafe_allow_html=True)
    
    # DOMAIN SELECTION (NEW)
    domain_opts = ["Network Traffic", "Authentication", "Endpoint / Process", "Application (Web/API)", "Asset / Inventory", "Security Alert", "DNS Log", "Cloud / Infra"]
    domain_sel = st.selectbox("Log Style (Domain)", domain_opts)
    
    log_volume = st.slider("Log Volume", 100, 100000, 1000, key="vol")
    st.caption("100 - 1000 - 10K - 100K")
    
    st.markdown('<div style="margin-top: 15px; font-weight:600; font-size:14px;">Time Pattern</div>', unsafe_allow_html=True)
    time_pattern = st.radio("Time Pattern", ["Steady", "Burst", "Low & Slow"], index=0, label_visibility="collapsed")
    
    st.write("")
    c1_btn1, c1_btn2 = st.columns([4, 4])
    with c1_btn1:
        gen_btn = st.button("Generate Logs", type="primary", use_container_width=True)
    with c1_btn2:
        clear_btn = st.button("Clear Logs", type="secondary", use_container_width=True)

with c2:
    st.markdown('<div class="card-header">Select Device Category</div>', unsafe_allow_html=True)
    dev_cats = {
        "Router": st.checkbox("Router", value=True),
        "IoT Camera": st.checkbox("IoT Camera", value=True),
        "Smart Sensor": st.checkbox("Smart Sensor", value=True),
        "Printer": st.checkbox("Printer", value=True),
        "Firewall Gateway": st.checkbox("Firewall Gateway", value=True),
        "VPN User": st.checkbox("VPN User", value=True)
    }

with c3:
    st.markdown('<div class="card-header">Baseline Traffic</div>', unsafe_allow_html=True)
    base_traffic = {
        "HTTP/DNS": st.checkbox("HTTP/DNS Office Traffic", value=True),
        "IoT Heartbeat": st.checkbox("IoT Heartbeat", value=True),
        "File Access": st.checkbox("Common File Access", value=True),
        "IoT Anomalies": st.checkbox("IoT Anomalies", value=True)
    }

with c4:
    st.markdown('<div class="card-header">Attacks</div>', unsafe_allow_html=True)
    # Dynamic Pattern Loading
    from pattern_manager import PatternManager
    pm = PatternManager()
    avail_patterns = pm.get_available_patterns()

    # Pre-select some common ones if available, or just defaulting
    # Storing selection in a dict
    pattern_selections = {}
    
    # Split into columns for better layout if many
    p_col1, p_col2 = st.columns(2)
    
    for i, pat in enumerate(avail_patterns):
        # We checkbox them. Default to False to avoid noise, or check first few?
        # User asked to "add these new attacks as checkboxes"
        with (p_col1 if i % 2 == 0 else p_col2):
            pattern_selections[pat] = st.checkbox(pat, value=False)
    
    # Existing hardcoded attacks (Legagy)
    st.markdown("---")
    c4_1, c4_2 = st.columns([3, 1])
    with c4_1:
        atk_scan = st.checkbox("Port Scanning", value=True)
        atk_ssh = st.checkbox("SSH Brute Force", value=True)
        atk_dns = st.checkbox("DNS Tunneling", value=True)
    
    with c4_2:
        # Generic input for pattern count
        n_pattern = st.number_input("N (Patterns)", 0, 100, 5, label_visibility="collapsed", key="n_pat")
        
        n_scan = st.number_input("N (Scan)", 0, 100, 5, label_visibility="collapsed", key="n1")
        n_ssh = st.number_input("N (SSH)", 0, 100, 3, label_visibility="collapsed", key="n2")
        n_dns = st.number_input("N (DNS)", 0, 100, 2, label_visibility="collapsed", key="n3")

st.markdown('</div>', unsafe_allow_html=True)

# --- 5. LOG GENERATION LOGIC ---
if gen_btn:
    with st.status("Generating Network Logs...", expanded=True) as status:
        # 1. Build Arguments
        # Baseline count is roughly the log volume minus attacks
        total_attacks = (n_scan if atk_scan else 0) + (n_ssh if atk_ssh else 0) + (n_dns if atk_dns else 0)
        baseline_count = max(0, log_volume - total_attacks)
        
        # Collect Categories
        selected_cats = [k for k, v in dev_cats.items() if v]
        cat_args = []
        if selected_cats:
            cat_args = ["--categories"] + selected_cats
        
        # Build Command
        # Use venv python if available, otherwise fallback
        import os
        python_exec = "./venv/bin/python" if os.path.exists("./venv/bin/python") else "python"
        
        # DOMAIN HANDLING
        # Map user friendly name to backend key
        dom_map = {
            "Network Traffic": "Network",
            "Authentication": "Authentication",
            "Endpoint / Process": "Endpoint",
            "Application (Web/API)": "Web",
            "Asset / Inventory": "Asset",
            "Security Alert": "Alert",
            "DNS Log": "DNS",
            "Cloud / Infra": "Cloud"
        }
        selected_dom_key = dom_map[domain_sel]
        
        cmd = [
            python_exec, "traffic_generator.py",
            "--baseline", str(baseline_count),
            "--domain", selected_dom_key
        ]
        
        # PATTERNS (New)
        selected_patterns = [p for p, selected in pattern_selections.items() if selected]
        if selected_patterns:
            # We pass a comma-separated string of patterns
            cmd.extend(["--patterns", ",".join(selected_patterns)])
            # Also pass the N per pattern
            cmd.extend(["--pattern_count", str(n_pattern)])

        # Only add attacks if domain is Network (default) or compatible
        if selected_dom_key == "Network" or True: # Allow attacks on any domain now
            if atk_ssh:
                cmd.extend(["--ssh", str(n_ssh)])
            if atk_dns:
                cmd.extend(["--dns", str(n_dns)])
            # Legacy mapping
            if atk_scan:
                 cmd.extend(["--beacon", str(n_scan)])
             
        cmd.extend(cat_args)
        
        st.write(f"Executing simulation engine...")
        # Run Generator
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                status.update(label="Generation Failed", state="error")
                st.error(res.stderr)
            else:
                st.write("Ingesting logs to database...")
                ingest = subprocess.run([python_exec, "ingest_logs.py"], capture_output=True, text=True)
                if ingest.returncode != 0:
                    status.update(label="Ingestion Failed", state="error")
                    st.error(ingest.stderr)
                else:
                    status.update(label=f"Successfully Generated {log_volume} Logs", state="complete", expanded=False)
                    st.toast("Logs generated and ingested successfully!")
                    st.cache_data.clear()
                    time.sleep(1)
                    st.rerun()
        except Exception as e:
            st.error(f"System Error: {e}")

# --- 5.1 CLEAR LOGS LOGIC ---
if clear_btn:
    try:
        with engine.connect() as conn:
            conn.execute(text("DELETE FROM alerts"))
            conn.execute(text("DELETE FROM logs"))
            conn.commit()
        st.toast("Access Logs Cleared Successfully")
        time.sleep(1)
        st.cache_data.clear()
        st.rerun()
    except Exception as e:
        st.error(f"Error clearing logs: {e}")

# --- 5.2 DIALOG FOR DETAILS ---
@st.dialog("Log Details", width="small")
def show_log_details_dialog(log_record):
    # Compact Header
    st.markdown(f"**Timestamp:** {log_record['timestamp']}")
    
    # Compact Columns using HTML for tighter control unlike st.metric
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"<div style='font-size:12px; color:#57606a;'>Source IP</div><div style='font-size:16px; font-weight:500;'>{log_record['src_ip']}</div>", unsafe_allow_html=True)
    with col2:
        st.markdown(f"<div style='font-size:12px; color:#57606a;'>Destination IP</div><div style='font-size:16px; font-weight:500;'>{log_record['dst_ip']}</div>", unsafe_allow_html=True)
    with col3:
        act_color = "#cf222e" if log_record['action'] == 'deny' else "#1a7f37"
        st.markdown(f"<div style='font-size:12px; color:#57606a;'>Action</div><div style='font-size:16px; font-weight:600; color:{act_color};'>{log_record['action'].upper()}</div>", unsafe_allow_html=True)
    
    st.divider()
    
    st.markdown("#### Full Log Data")
    st.json(log_record.to_dict())
    
    if log_record.get('raw_log'):
        st.markdown("#### Raw Log")
        st.code(log_record['raw_log'], language='text')

# --- 6. DATA FETCHING ---
@st.cache_data(ttl=5)
def get_data():
    conn = get_db_connection()
    conn = get_db_connection()
    try:
        # Fetch detailed logs
        print("DEBUG: Fetching data from DB...")
        df = pd.read_sql("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 1000", conn)
        print(f"DEBUG: Data fetched. Shape: {df.shape}")
        if not df.empty:
            print(f"DEBUG: Columns: {df.columns.tolist()}")
            print(f"DEBUG: First row: {df.iloc[0].to_dict()}")
        else:
            print("DEBUG: Dataframe is empty.")
        
        # Ensure timestamp is datetime
        if not df.empty and 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
        return df
    except Exception as e:
        print(f"DEBUG: Error fetching data: {e}")
        st.error(f"Error fetching data: {e}")
        return pd.DataFrame()

df_logs = get_data()


# --- 7. LOGS TABLE SECTION ---
st.markdown('<div class="custom-card">', unsafe_allow_html=True)

# Filters Toolbar
f1, f2, f3, f4, f5 = st.columns([1, 1, 1, 1, 0.5])
with f1:
    st.selectbox("Time Period", ["Last 1 hour", "Last 24 hours"], label_visibility="collapsed")
with f2:
    st.selectbox("Device/IP", ["All Devices"], label_visibility="collapsed")
with f3:
    st.selectbox("Device Type", ["All Types"] + list(dev_cats.keys()), label_visibility="collapsed")
with f4:
    st.selectbox("Attack Type", ["All Attacks"], label_visibility="collapsed")
with f5:
    st.selectbox("Action", ["Any"], label_visibility="collapsed")

st.markdown("---")

if not df_logs.empty:
    # 7.1 Data Preparation
    display_df = df_logs.copy()
    display_df['Device Type'] = display_df['device_type'] if 'device_type' in display_df.columns else 'Unknown'
    display_df['Attack Type'] = display_df.apply(lambda x: "SSH Brute Force" if x['dst_port'] == 22 and x['action'] == 'deny' else ("DNS Tunneling" if x['dst_port'] == 53 and x['sentbyte'] > 1000 else "Normal Traffic"), axis=1)
    
    # 7.2 Legend
    st.markdown("""
    <div style="display: flex; gap: 15px; margin-bottom: 10px; font-size: 12px; font-weight: 600;">
        <div style="display:flex; align-items:center;"><span style="display:inline-block; width:10px; height:10px; background-color:#ffebe9; border:1px solid #cf222e; margin-right:5px;"></span> SSH Brute Force</div>
        <div style="display:flex; align-items:center;"><span style="display:inline-block; width:10px; height:10px; background-color:#fbefff; border:1px solid #8250df; margin-right:5px;"></span> DNS Tunneling</div>
        <div style="display:flex; align-items:center;"><span style="display:inline-block; width:10px; height:10px; background-color:#ffffff; border:1px solid #d0d7de; margin-right:5px;"></span> Normal Traffic</div>
    </div>
    """, unsafe_allow_html=True)

    # 7.3 Styling Function
    def highlight_attacks(row):
        atk = row['Attack Type']
        if "SSH" in atk:
            return ['background-color: #ffebe9; color: #cf222e'] * len(row)
        elif "DNS" in atk:
            return ['background-color: #fbefff; color: #8250df'] * len(row)
        return [''] * len(row)

    # 7.4 Pagination Logic
    if 'page_number' not in st.session_state:
        st.session_state.page_number = 1
    
    page_size = 15
    total_pages = max(1, (len(display_df) + page_size - 1) // page_size)
    
    c_pag1, c_pag2, c_pag3 = st.columns([2, 6, 2])
    with c_pag1:
        if st.button("Previous"):
            if st.session_state.page_number > 1:
                st.session_state.page_number -= 1
                st.rerun()
    with c_pag2:
        st.write(f"Page {st.session_state.page_number} of {total_pages}")
    with c_pag3:
        if st.button("Next"):
            if st.session_state.page_number < total_pages:
                st.session_state.page_number += 1
                st.rerun()

    # Create the dataframe for the current page
    page_start = (st.session_state.page_number - 1) * page_size
    page_end = page_start + page_size
    page_df = display_df.iloc[page_start:page_end]

    # Select columns for display
    # DYNAMIC COLUMN VISIBILITY: Show columns that have at least one non-null value (ignoring 'id', 'raw_log', etc if wanted)
    # But usually we want specific columns first.
    
    # 1. Base Columns (always first)
    base_cols = ['timestamp', 'log_type', 'src_ip', 'user']
    
    # 2. Get all other columns that are not null in this page (or whole set?)
    # Optimization: Check current page for non-nulls
    non_null_cols = page_df.columns[page_df.notna().any()].tolist()
    
    # 3. Filter out internals
    exclude = ['id', 'raw_log', 'created_at', 'logid', 'qname', 'msg', 'srccountry', 'dstcountry'] + base_cols
    dynamic_cols = [c for c in non_null_cols if c not in exclude]
    
    # 4. Final View List
    view_cols = base_cols + dynamic_cols
    
    # Ensure they confirm to df
    view_cols = [c for c in view_cols if c in page_df.columns]

    styled_df = page_df[view_cols].style.apply(highlight_attacks, axis=1)

    # 7.5 Interactive Table
    event = st.dataframe(
        styled_df,
        use_container_width=True,
        hide_index=True,
        selection_mode="single-row",
        on_select="rerun"
    )

    # 7.6 Log Details View
    if event and event.selection['rows']:
        selected_index = event.selection['rows'][0]
        # Map back to original dataframe (the page_df) using iloc
        selected_log = page_df.iloc[selected_index]
        show_log_details_dialog(selected_log)

    # Footer Actions
    st.markdown("---")
    c_foot1, c_foot2 = st.columns([6, 1])
    with c_foot2:
        st.markdown('<div style="display:flex; gap:10px;">', unsafe_allow_html=True)
        st.button("Download XLSX", key="dl_xlsx")
        st.button("JSON", key="dl_json")
        st.markdown('</div>', unsafe_allow_html=True)

else:
    st.info("No logs found. Generate traffic to see data.")

st.markdown('</div>', unsafe_allow_html=True)
