# LogShield
# Imports
import streamlit as st
import pandas as pd
import numpy as np
import re
import altair as alt
import math
from datetime import datetime
from fpdf import FPDF
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from io import BytesIO

# Page configuration
st.set_page_config(
    page_title="LogShield | SOC-Grade Anomaly Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS / Styling
st.markdown("""
    <style>
    .stApp { background-color: #0E1117; color: #E0E0E0; }
    div.stButton > button:first-child { background-color: #00FF7F; color: #000; font-weight: bold; }
    div[data-testid="stMetricValue"] { font-size: 24px; color: #00FF7F; }
    </style>
""", unsafe_allow_html=True)

# Vectorized log parsing
@st.cache_data
def parse_access_log_vectorized(log_content: str) -> pd.DataFrame:
    """
    Uses Pandas Vectorized String Operations instead of Python Loops.
    """
    # Create a Series from the log lines
    lines = pd.Series(log_content.splitlines())
    lines = lines[lines.str.strip() != ""] # Remove empty lines

    if lines.empty:
        return pd.DataFrame()

    # Regex for Common Log Format (CLF) / Combined
    # Captures: IP, Time, Method, Resource, Status, Size
    regex = r'(?P<ip>[\d\.]+)\s+\S+\s+\S+\s+\[(?P<time>.*?)\]\s+"(?P<method>[A-Z]+)\s+(?P<resource>.*?)\s+HTTP/[0-9\.]+"\s+(?P<status>\d{3})\s+(?P<size>[\d-]+)'
    
    # Extract data using C-optimized Pandas backend
    df = lines.str.extract(regex)
    
    # Handle rows that didn't match strict regex (Fallbacks)
    # For a production SOC tool, we'd log these parsing failures separately
    df = df.dropna(subset=['ip', 'method']) 

    # Type Conversion
    df['size'] = pd.to_numeric(df['size'].replace('-', 0), errors='coerce').fillna(0).astype(int)
    df['status'] = pd.to_numeric(df['status'], errors='coerce').fillna(0).astype(int)
    
    # Parse Time (Optimized)
    # We keep the original string for display, but could parse to datetime if needed for plotting
    try:
        df['datetime'] = pd.to_datetime(df['time'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce')
    except:
        df['datetime'] = datetime.now()

    return df

# Feature engineering for SOC analysis
def calculate_entropy(text):
    """Calculates Shannon Entropy to detect random strings (tunnels/shells)."""
    if not text: return 0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return - sum([p * math.log(p) / math.log(2.0) for p in prob])

@st.cache_data
def extract_features(df: pd.DataFrame):
    """
    Generates features focused on Attack Vectors (SQLi, Shells, Scanners).
    """
    working = df.copy()
    
    # 1. Structural Features
    working['url_length'] = working['resource'].str.len()
    working['param_count'] = working['resource'].str.count(r'[\?\&]')
    working['directory_depth'] = working['resource'].str.count('/')
    
    # 2. Entropy Analysis (Detects encrypted payloads or random generation)
    # Using a lambda here is necessary, but we apply it only to unique values to speed it up
    unique_resources = working['resource'].unique()
    entropy_map = {res: calculate_entropy(res) for res in unique_resources}
    working['entropy'] = working['resource'].map(entropy_map)

    # 3. Categorical Encoding
    method_map = {'GET': 1, 'HEAD': 1, 'POST': 5, 'PUT': 10, 'DELETE': 10, 'PATCH': 8, 'CONNECT': 20}
    working['method_score'] = working['method'].map(method_map).fillna(5)
    
    # 4. Status Logic (404 scans vs 500 exploits)
    working['is_error'] = working['status'].apply(lambda x: 10 if x >= 500 else (5 if x >= 400 else 0))
    
    # 5. IP Frequency (Vectorized)
    # transform('count') is faster than map(value_counts)
    working['ip_count'] = working.groupby('ip')['ip'].transform('count')
    working['ip_rarity'] = 1 / working['ip_count']

    # Final Feature Set
    feature_cols = ['size', 'url_length', 'param_count', 'directory_depth', 
                   'entropy', 'method_score', 'is_error', 'ip_rarity']
    
    scaler = StandardScaler()
    features_scaled = scaler.fit_transform(working[feature_cols].fillna(0))
    
    return features_scaled, working

# Model training and reporting utilities
def train_and_predict(features_np, contamination=0.01):
    model = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)
    model.fit(features_np)
    
    preds = model.predict(features_np) # -1 = Anomaly
    scores = model.decision_function(features_np) # Lower = more anomalous
    
    return preds, scores

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'LogShield Pro - Security Incident Report', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(anomalies_df):
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    
    pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.cell(0, 10, f"Total Critical Anomalies: {len(anomalies_df)}", ln=True)
    pdf.ln(5)
    
    # Table Header
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(40, 8, "IP Address", 1)
    pdf.cell(20, 8, "Method", 1)
    pdf.cell(20, 8, "Status", 1)
    pdf.cell(30, 8, "Risk Score", 1)
    pdf.cell(0, 8, "Resource (Truncated)", 1, 1)
    
    pdf.set_font("Arial", size=9)
    for _, row in anomalies_df.head(50).iterrows():
        # Sanitize strings to prevent PDF encoding crashes (common SOC issue)
        res_clean = row['resource'][:40].encode('latin-1', 'replace').decode('latin-1')
        ip_clean = str(row['ip'])
        
        pdf.cell(40, 8, ip_clean, 1)
        pdf.cell(20, 8, str(row['method']), 1)
        pdf.cell(20, 8, str(row['status']), 1)
        pdf.cell(30, 8, f"{row['Anomaly Score']:.3f}", 1)
        pdf.cell(0, 8, res_clean, 1, 1)
        
    return pdf.output(dest='S').encode('latin-1', 'replace')

# Main dashboard / UI
def main():
    st.title("🛡️ LogShield Pro | SOC Edition")
    st.markdown("### Automated Threat Hunting & Anomaly Detection")
    
    with st.sidebar:
        st.header("Configuration")
        uploaded_file = st.file_uploader("Upload Access Log", type=["log", "txt", "csv"])
        st.divider()
        sensitivity = st.slider("Model Sensitivity", 0.001, 0.1, 0.02, format="%.3f",
                              help="Higher = More alerts (potentially more False Positives)")
        
    if uploaded_file:
        try:
            raw_data = uploaded_file.getvalue().decode("utf-8")
        except:
            raw_data = uploaded_file.getvalue().decode("latin-1") # Fallback for binary logs
            
        with st.status("🚀 Ingesting & Analyzing Data...", expanded=True) as status:
            st.write("Parsing raw logs (Vectorized)...")
            df = parse_access_log_vectorized(raw_data)
            
            if df.empty:
                status.update(label="Parsing Failed", state="error")
                st.error("Could not parse logs. Ensure CLF/Combined format.")
                st.stop()
                
            st.write(f"Extracting features for {len(df)} events...")
            features_scaled, full_df = extract_features(df)
            
            st.write("Running Isolation Forest...")
            preds, scores = train_and_predict(features_scaled, sensitivity)
            
            full_df['Anomaly'] = preds
            full_df['Anomaly Score'] = scores
            status.update(label="Analysis Complete", state="complete")

        # Results and exports
        anomalies = full_df[full_df['Anomaly'] == -1].sort_values(by="Anomaly Score")
        
        # KPI Row
        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Events Analyzed", len(full_df))
        k2.metric("Threats Detected", len(anomalies), delta_color="inverse")
        k3.metric("Avg. Entropy", f"{full_df['entropy'].mean():.2f}")
        k4.metric("Max Risk Score", f"{anomalies['Anomaly Score'].min():.3f}" if not anomalies.empty else "0")

        if not anomalies.empty:
            tab1, tab2, tab3 = st.tabs(["🚨 Threat Feed", "📈 Visual Analytics", "📝 Export"])
            
            with tab1:
                st.subheader("Critical Anomalies")
                # Highlight critical columns
                st.dataframe(
                    anomalies[['datetime', 'ip', 'method', 'status', 'resource', 'entropy', 'Anomaly Score']].head(100),
                    column_config={
                        "Anomaly Score": st.column_config.ProgressColumn("Risk Level", format="%.3f", min_value=-0.5, max_value=0),
                        "entropy": st.column_config.NumberColumn("Payload Entropy"),
                    },
                    use_container_width=True
                )
            
            with tab2:
                # Time Series of Anomalies
                st.subheader("Attack Timeline")
                if 'datetime' in anomalies.columns:
                    # Round to nearest hour for plotting
                    timeline_df = anomalies.copy()
                    timeline_df['hour'] = timeline_df['datetime'].dt.floor('H')
                    chart_data = timeline_df.groupby('hour').size().reset_index(name='Count')
                    
                    chart = alt.Chart(chart_data).mark_area(
                        line={'color':'#ff2b2b'},
                        color=alt.Gradient(
                            gradient='linear',
                            stops=[alt.GradientStop(color='#ff2b2b', offset=1),
                                   alt.GradientStop(color='#ff2b2b00', offset=0)],
                            x1=1, x2=1, y1=1, y2=0
                        )
                    ).encode(
                        x='hour:T',
                        y='Count:Q',
                        tooltip=['hour', 'Count']
                    ).properties(height=300)
                    st.altair_chart(chart, use_container_width=True)

                # Scatter Plot: Entropy vs URL Length
                st.subheader("Payload Analysis (Entropy vs Length)")
                scatter = alt.Chart(anomalies).mark_circle(size=60).encode(
                    x='url_length',
                    y='entropy',
                    color='method',
                    tooltip=['resource', 'ip', 'Anomaly Score']
                ).interactive()
                st.altair_chart(scatter, use_container_width=True)

            with tab3:
                pdf_data = generate_pdf_report(anomalies)
                st.download_button(
                    label="📄 Download Executive Report (PDF)",
                    data=BytesIO(pdf_data),
                    file_name=f"Threat_Report_{datetime.now().strftime('%Y%m%d')}.pdf",
                    mime='application/pdf'
                )

        else:
            st.balloons()
            st.success("System Clean: No anomalies detected within current sensitivity threshold.")

if __name__ == "__main__":
    main()
