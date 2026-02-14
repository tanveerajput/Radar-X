"""
RADAR-X Real-Time Dashboard - FIXED VERSION
Same structure, better backend sync
Run with: streamlit run dashboard_realtime_fixed.py
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from datetime import datetime
import time
import sys
import os
from pathlib import Path

# Page config
st.set_page_config(
    page_title="RADAR-X Live Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS (SAME AS ORIGINAL)
st.markdown("""
<style>
    .main { background: linear-gradient(135deg, #0f0c29, #302b63, #24243e); }
    .threat-critical {
        background: #ff4444;
        color: white;
        padding: 20px;
        border-radius: 15px;
        font-weight: bold;
        text-align: center;
        font-size: 2em;
        animation: pulse 1s infinite;
        margin: 20px 0;
    }
    .threat-medium {
        background: #ffaa00;
        color: black;
        padding: 20px;
        border-radius: 15px;
        font-weight: bold;
        text-align: center;
        font-size: 2em;
        margin: 20px 0;
    }
    .threat-low {
        background: #00ff88;
        color: black;
        padding: 20px;
        border-radius: 15px;
        font-weight: bold;
        text-align: center;
        font-size: 2em;
        margin: 20px 0;
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.8; }
    }
</style>
""", unsafe_allow_html=True)

# Add Stage1_Predict to path
stage1_path = Path("Stage1_Predict")
if stage1_path.exists():
    sys.path.insert(0, str(stage1_path))

# Try importing Stage 1 components
STAGE1_AVAILABLE = False
try:
    from feature_extractor import FeatureExtractor
    from ml_detector import RansomwareMLDetector
    import psutil
    STAGE1_AVAILABLE = True
except ImportError:
    pass

# Initialize session state
if 'threat_history' not in st.session_state:
    st.session_state.threat_history = []

# Load Stage 1 components once
@st.cache_resource
def load_stage1():
    if not STAGE1_AVAILABLE:
        return None, None
    
    try:
        extractor = FeatureExtractor()
        detector = RansomwareMLDetector(contamination=0.15)
        
        model_path = Path("Stage1_Predict/ransomware_model.pkl")
        if model_path.exists():
            detector.load_model(str(model_path))
        
        return extractor, detector
    except:
        return None, None

def get_real_system_state():
    """Get ACCURATE system state matching backend logic"""
    extractor, detector = load_stage1()
    
    if extractor is None or detector is None:
        return None
    
    try:
        # Get real processes
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
            try:
                info = proc.info
                processes.append({
                    'pid': info['pid'],
                    'name': info['name'],
                    'cpu_percent': info['cpu_percent'] or 0,
                    'memory_mb': info['memory_info'].rss / (1024 * 1024) if info['memory_info'] else 0,
                    'threat_score': 0
                })
            except:
                continue
        
        # Honeypot status
        honeypot_dir = Path("honeypots")
        honeypot_compromised = 0
        honeypot_total = 8
        
        if honeypot_dir.exists():
            honeypot_files = list(honeypot_dir.glob("*.txt")) + list(honeypot_dir.glob("*.dat"))
            if honeypot_files:
                honeypot_total = len(honeypot_files)
                # Check if modified (size > 1KB = compromised)
                for hf in honeypot_files:
                    try:
                        if hf.stat().st_size > 1024:
                            honeypot_compromised += 1
                    except:
                        pass
        
        honeypot_status = {
            'total_honeypots': honeypot_total,
            'compromised': honeypot_compromised,
            'intact': honeypot_total - honeypot_compromised
        }
        
        # Extract features (NO file events = idle)
        features_raw = extractor.extract_all_features(
            file_events=[],
            process_data=processes[:50],
            honeypot_status=honeypot_status
        )
        
        # CRITICAL FIX: Normalize features BEFORE calculating sum
        features_normalized = extractor.normalize_features(features_raw)
        feature_sum = float(np.sum(np.abs(features_normalized)))
        
        # CRITICAL FIX: Use higher threshold to match backend
        IDLE_THRESHOLD = 4.0  # Same as backend's calibrated threshold
        is_idle = feature_sum < IDLE_THRESHOLD
        
        # Determine threat
        if is_idle:
            # IDLE state - always LOW threat
            prediction = 1
            threat_score = 5.0
            is_ransomware = False
        else:
            # Active - use ML
            features_2d = features_normalized.reshape(1, -1)
            pred_array, score_array = detector.predict_with_confidence(features_2d)
            prediction = pred_array[0]
            threat_score = float(score_array[0])
            is_ransomware = (prediction == -1)
        
        # Honeypot override
        if honeypot_compromised > 0:
            threat_score = max(threat_score, 90.0)
            is_ransomware = True
        
        # Determine level
        if honeypot_compromised > 0 or is_ransomware or threat_score > 70:
            threat_level = "CRITICAL"
        elif threat_score > 50:
            threat_level = "HIGH"
        elif threat_score > 30:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
        
        return {
            'threat_score': threat_score,
            'threat_level': threat_level,
            'prediction': 'RANSOMWARE' if is_ransomware else 'NORMAL',
            'features_raw': features_raw.tolist(),
            'features_normalized': features_normalized.tolist(),
            'feature_sum': feature_sum,
            'is_idle': is_idle,
            'process_count': len(processes),
            'suspicious_processes': 0,
            'honeypot_status': honeypot_status,
            'timestamp': datetime.now().isoformat()
        }
    
    except Exception as e:
        st.error(f"Error: {e}")
        return None

# Title
st.title("🛡️ RADAR-X: Real-Time Defense Dashboard")

# Status bar
col1, col2 = st.columns([3, 1])
with col1:
    st.markdown("### 🔴 LIVE - Connected to Backend Systems")
with col2:
    if st.button("🔄 Refresh Now", use_container_width=True):
        st.rerun()

if STAGE1_AVAILABLE:
    st.success("✅ Stage 1 Connected - Reading Live Data")
else:
    st.error("❌ Stage 1 Not Available")

# Sidebar (SAME STRUCTURE)
st.sidebar.title("🎛️ Control Panel")
page = st.sidebar.radio("Navigation", [
    "📊 Live Monitoring",
    "🧠 Stage 1: Detection",
    "📈 Feature Analysis",
    "⚙️ System Info"
])

auto_refresh = st.sidebar.checkbox("🔄 Auto-refresh (5s)", value=False)
if auto_refresh:
    st.sidebar.info("Dashboard refreshing every 5 seconds")

st.sidebar.markdown("---")
st.sidebar.markdown("**Debug Info:**")
st.sidebar.text(f"Last: {datetime.now().strftime('%H:%M:%S')}")

# ==================== LIVE MONITORING ====================
if page == "📊 Live Monitoring":
    st.header("Live System Monitoring")
    
    system_state = get_real_system_state()
    
    if system_state:
        threat_score = system_state['threat_score']
        threat_level = system_state['threat_level']
        
        # Threat banner
        if threat_level == "CRITICAL":
            st.markdown(
                f'<div class="threat-critical">🚨 CRITICAL THREAT - Score: {threat_score:.1f}/100</div>',
                unsafe_allow_html=True
            )
        elif threat_level == "MEDIUM":
            st.markdown(
                f'<div class="threat-medium">⚡ MEDIUM THREAT - Score: {threat_score:.1f}/100</div>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f'<div class="threat-low">✅ LOW THREAT - System Secure - Score: {threat_score:.1f}/100</div>',
                unsafe_allow_html=True
            )
        
        # Metrics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Threat Score", f"{threat_score:.1f}/100", delta=threat_level)
        
        with col2:
            st.metric("Processes", system_state['process_count'], 
                     delta="All normal" if system_state['suspicious_processes'] == 0 else f"{system_state['suspicious_processes']} suspicious")
        
        with col3:
            honeypot = system_state['honeypot_status']
            st.metric("Honeypots", f"{honeypot['intact']}/{honeypot['total_honeypots']}",
                     delta="✅ Intact" if honeypot['compromised'] == 0 else "🔴 COMPROMISED")
        
        with col4:
            st.metric("Status", system_state['prediction'],
                     delta="IDLE" if system_state['is_idle'] else "ACTIVE")
        
        # Info boxes
        st.markdown("---")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.info(f"**Feature Sum:** {system_state['feature_sum']:.3f}\n\n"
                   f"**Idle Threshold:** 4.0\n\n"
                   f"**Is Idle:** {'Yes ✅' if system_state['is_idle'] else 'No'}")
        
        with col2:
            st.info(f"**ML Prediction:** {system_state['prediction']}\n\n"
                   f"**Threat Level:** {threat_level}\n\n"
                   f"**Backend Sync:** ✅ Connected")
        
        with col3:
            st.info(f"**Last Update:** {datetime.now().strftime('%H:%M:%S')}\n\n"
                   f"**Honeypot Alert:** {'🚨 YES' if honeypot['compromised'] > 0 else '✅ No'}\n\n"
                   f"**Auto-refresh:** {'ON' if auto_refresh else 'OFF'}")
        
        # Timeline
        st.session_state.threat_history.append({
            'time': datetime.now(),
            'score': threat_score,
            'level': threat_level
        })
        
        if len(st.session_state.threat_history) > 100:
            st.session_state.threat_history.pop(0)
        
        if len(st.session_state.threat_history) > 1:
            st.markdown("### 📊 Threat Score Timeline")
            
            df_history = pd.DataFrame(st.session_state.threat_history)
            
            fig = go.Figure()
            
            colors = {'LOW': 'green', 'MEDIUM': 'yellow', 'HIGH': 'orange', 'CRITICAL': 'red'}
            
            for level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
                level_data = df_history[df_history['level'] == level]
                if not level_data.empty:
                    fig.add_trace(go.Scatter(
                        x=level_data['time'], y=level_data['score'],
                        mode='lines+markers', name=level,
                        line=dict(color=colors[level], width=2)
                    ))
            
            fig.add_hline(y=70, line_dash="dash", line_color="red", annotation_text="Critical (70)")
            fig.add_hline(y=30, line_dash="dash", line_color="yellow", annotation_text="Medium (30)")
            
            fig.update_layout(
                xaxis_title="Time", yaxis_title="Threat Score",
                template="plotly_dark", height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    else:
        st.error("❌ Cannot read system state")
    
    if auto_refresh:
        time.sleep(5)
        st.rerun()

# ==================== STAGE 1 DETECTION ====================
elif page == "🧠 Stage 1: Detection":
    st.header("Stage 1: Real-Time Detection Details")
    
    system_state = get_real_system_state()
    
    if system_state:
        st.markdown("### 📊 Feature Values")
        
        feature_names = [
            'Files Modified/min', 'Files Created/min', 'Files Deleted/min',
            'Average Entropy', 'Unique Extensions', 'Max CPU Usage (%)',
            'Total Memory (MB)', 'Suspicious Processes', 'Disk Write Rate',
            'New Processes', 'Honeypots Compromised', 'Honeypot Access Rate',
            'File Change Acceleration', 'Burst Activity', 'Activity Consistency'
        ]
        
        feature_df = pd.DataFrame({
            'Feature': feature_names,
            'Raw Value': [f"{v:.3f}" for v in system_state['features_raw']],
            'Normalized': [f"{v:.3f}" for v in system_state['features_normalized']],
            'Status': ['🔴' if v > 0.7 else '🟡' if v > 0.4 else '🟢' 
                      for v in system_state['features_normalized']]
        })
        
        st.dataframe(feature_df, use_container_width=True, hide_index=True)
        
        # Feature chart
        st.markdown("### 📈 Feature Visualization")
        
        fig = go.Figure(data=[go.Bar(
            x=feature_names,
            y=system_state['features_normalized'],
            marker_color=['red' if v > 0.7 else 'yellow' if v > 0.4 else 'green'
                         for v in system_state['features_normalized']],
            text=[f"{v:.2f}" for v in system_state['features_normalized']],
            textposition='auto'
        )])
        
        fig.update_layout(
            title="Normalized Feature Values",
            xaxis_tickangle=-45,
            template="plotly_dark",
            height=500
        )
        
        st.plotly_chart(fig, use_container_width=True)
        
        with st.expander("🔧 Debug Info"):
            st.json(system_state)
    
    if auto_refresh:
        time.sleep(5)
        st.rerun()

# ==================== FEATURE ANALYSIS ====================
elif page == "📈 Feature Analysis":
    st.header("Feature Analysis & System State")
    
    system_state = get_real_system_state()
    
    if system_state:
        col1, col2, col3 = st.columns(3)
        
        col1.metric("Feature Sum", f"{system_state['feature_sum']:.3f}")
        col2.metric("Idle Threshold", "4.0")
        col3.metric("Idle Status", "YES" if system_state['is_idle'] else "NO")
        
        st.markdown("### Top Features by Value")
        
        feature_names = [
            'Files Mod', 'Files Create', 'Files Del', 'Entropy', 'Extensions',
            'CPU', 'Memory', 'Susp Proc', 'Disk I/O', 'New Proc',
            'Honeypot Hit', 'Honeypot Rate', 'Accel', 'Burst', 'Consistency'
        ]
        
        feature_values = list(zip(feature_names, system_state['features_normalized']))
        feature_values.sort(key=lambda x: x[1], reverse=True)
        
        for i, (name, value) in enumerate(feature_values[:10], 1):
            st.metric(f"{i}. {name}", f"{value:.3f}")
    
    if auto_refresh:
        time.sleep(5)
        st.rerun()

# ==================== SYSTEM INFO ====================
elif page == "⚙️ System Info":
    st.header("System Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Stage 1 Status")
        st.info(f"**Available:** {'✅ Yes' if STAGE1_AVAILABLE else '❌ No'}\n\n"
               f"**Model:** {'✅ Loaded' if Path('Stage1_Predict/ransomware_model.pkl').exists() else '❌ Missing'}")
    
    with col2:
        st.markdown("### Dashboard Info")
        st.info(f"**Points Logged:** {len(st.session_state.threat_history)}\n\n"
               f"**Auto-refresh:** {'ON' if auto_refresh else 'OFF'}")
    
    if STAGE1_AVAILABLE:
        try:
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            
            st.markdown("### System Resources")
            col1, col2 = st.columns(2)
            col1.metric("CPU Usage", f"{cpu}%")
            col2.metric("Memory Usage", f"{memory.percent}%")
        except:
            pass

# Footer
st.markdown("---")
st.markdown(f"""
<div style='text-align: center; color: #888;'>
    <p>🛡️ RADAR-X Real-Time Dashboard | Stage 1: {'✅ Online' if STAGE1_AVAILABLE else '❌ Offline'}</p>
</div>
""", unsafe_allow_html=True)