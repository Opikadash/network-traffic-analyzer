import signal, time, threading, smtplib, sqlite3, os
from queue import Queue, Empty
from scapy.all import sniff, wrpcap, IP
from analyzer.stats import StatsTracker
from analyzer.filter_ml import MLAnomalyDetector
from analyzer.portscan import detect_port_scan
from dotenv import load_dotenv
load_dotenv()  # Loads variables from .env file
import dash
from dash import dcc, html, Input, Output, State
import plotly.graph_objs as go
from email.mime.text import MIMEText
from datetime import datetime

# Global flags and queues
running = True
captured_packets = []
packet_queue = Queue()
stats = StatsTracker()
anomaly_threshold = 10  # % threshold for email alert
last_alert_time = 0
alert_interval = 300  # seconds
ml_detector = MLAnomalyDetector()  # Initialize early

# Initialize database
def init_db():
    os.makedirs("results", exist_ok=True)
    conn = sqlite3.connect("results/packet_logs.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packet_logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            protocol TEXT,
            is_anomaly INTEGER
        )
    """)
    conn.commit()
    conn.close()

# Setup SQLite logging
def log_to_db(packet, is_anomaly):
    conn = sqlite3.connect("results/packet_logs.db")
    cursor = conn.cursor()
    proto = stats.get_protocol(packet)
    src = packet[IP].src if packet.haslayer(IP) else "N/A"
    dst = packet[IP].dst if packet.haslayer(IP) else "N/A"
    cursor.execute("INSERT INTO packet_logs (timestamp, src_ip, dst_ip, protocol, is_anomaly) VALUES (?, ?, ?, ?, ?)", (
        datetime.now().isoformat(), src, dst, proto, int(is_anomaly)
    ))
    conn.commit()
    conn.close()

# Email alert
def send_email_alert(rate):
    global last_alert_time
    if time.time() - last_alert_time < alert_interval:
        return
    
    smtp_server = os.getenv("NET_SMTP_SERVER", "")
    smtp_port = os.getenv("NET_SMTP_PORT", "")
    smtp_user = os.getenv("NET_EMAIL_USER", "")
    smtp_pass = os.getenv("NET_EMAIL_PASS", "")
    email_to = os.getenv("NET_EMAIL_TO", "")
    
    # Skip if email not configured
    if not all([smtp_server, smtp_port, smtp_user, smtp_pass, email_to]):
        print("Email not configured. Skipping alert.")
        last_alert_time = time.time()
        return
        
    last_alert_time = time.time()

    body = f"🚨 ALERT: High anomaly rate detected: {rate}%"
    msg = MIMEText(body)
    msg["Subject"] = "Network Anomaly Alert"
    msg["From"] = smtp_user
    msg["To"] = email_to

    try:
        with smtplib.SMTP(smtp_server, int(smtp_port)) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
            print("Email alert sent successfully")
    except smtplib.SMTPAuthenticationError:
        print("\n" + "!" * 50)
        print("⚠️ SMTP AUTHENTICATION FAILURE ⚠️")
        print("1. Did you enable 2-Step Verification?")
        print("2. Did you generate an APP PASSWORD (not your regular password)?")
        print("3. Try visiting: https://accounts.google.com/DisplayUnlockCaptcha")
        print("4. Check your .env file for correct credentials")
        print("!" * 50)
    except Exception as e:
        print(f"Email sending error: {e}")

# SIGINT handler
def signal_handler(sig, frame):
    global running
    print("\n[*] Stopping capture...")
    running = False

# Initialize before threads start
init_db()

# Dash app setup
app = dash.Dash(__name__)
app.layout = html.Div([
    html.H2("Network Traffic Analyzer - Live Dashboard"),
    html.Div([
        html.Label("Filter by Protocol:"),
        dcc.Dropdown(id="protocol-filter", options=[
            {"label": proto, "value": proto} for proto in ["ALL", "TCP", "UDP", "ICMP", "DNS", "OTHER"]
        ], value="ALL", style={"width": "200px"})
    ]),
    dcc.Graph(id="anomaly-pie"),
    dcc.Graph(id="protocol-bar"),
    dcc.Graph(id="timeseries-graph"),
    html.Button("Export Packets", id="export-btn"),
    html.Div(id="export-status"),
    dcc.Interval(id="interval-component", interval=2000, n_intervals=0)
])

@app.callback(
    [Output("anomaly-pie", "figure"),
     Output("protocol-bar", "figure"),
     Output("timeseries-graph", "figure"),
     Output("export-status", "children")],
    [Input("interval-component", "n_intervals"),
     Input("export-btn", "n_clicks"),
     Input("protocol-filter", "value")],
    prevent_initial_call=False
)
def update_graphs(n, export_clicks, selected_protocol):
    report = stats.report(selected_protocol if selected_protocol != "ALL" else None)
    ts_data = stats.get_time_series(selected_protocol if selected_protocol != "ALL" else None)

    # Anomaly pie
    anomaly_fig = go.Figure(data=[
        go.Pie(labels=["Normal", "Anomalies"],
               values=[report["Total Packets"] - report["Anomalies Detected"],
                       report["Anomalies Detected"]], hole=0.4)
    ])
    anomaly_fig.update_layout(title="Anomaly Distribution")

    # Protocol bar
    proto_labels = [k.replace(" Packets", "") for k in report if "Packets" in k and k != "Total Packets"]
    proto_values = [v for k, v in report.items() if "Packets" in k and k != "Total Packets"]
    protocol_fig = go.Figure(data=[go.Bar(x=proto_labels, y=proto_values)])
    protocol_fig.update_layout(title="Protocol Packet Count", yaxis_title="Count")

    # Time-series
    time_fig = go.Figure()
    time_fig.add_trace(go.Scatter(x=list(ts_data.keys()), y=list(ts_data.values()),
                                  mode="lines+markers", name="Packet Count"))
    time_fig.update_layout(title="Packet Count Over Time", xaxis_title="Time", yaxis_title="Packets")

    # Export status
    export_msg = ""
    ctx = dash.callback_context
    if ctx.triggered and "export-btn" in ctx.triggered[0]["prop_id"]:
        os.makedirs("results", exist_ok=True)
        wrpcap("results/exported_packets.pcap", captured_packets)
        export_msg = "Exported packets to results/exported_packets.pcap"

    return anomaly_fig, protocol_fig, time_fig, export_msg

def packet_worker():
    while running:
        try:
            pkt = packet_queue.get(timeout=1)
            is_anomaly = ml_detector.is_anomalous(pkt) or detect_port_scan(pkt)
            stats.update(pkt, is_anomaly)
            captured_packets.append(pkt)
            log_to_db(pkt, is_anomaly)
            if stats.report()["Anomaly Rate (%)"] > anomaly_threshold:
                send_email_alert(stats.report()["Anomaly Rate (%)"])
        except Empty:
            continue
        except Exception as e:
            print(f"Error processing packet: {e}")

def capture_loop():
    print("[*] Starting packet capture...")
    while running:
        try:
            packets = sniff(count=10, timeout=1)
            for pkt in packets:
                packet_queue.put(pkt)
        except Exception as e:
            print(f"Capture error: {e}")

if __name__ == "__main__":
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Ensure results directory exists
    os.makedirs("results", exist_ok=True)
    
    print("[*] Warming up ML model...")
    try:
        # Capture packets for training
        sample_packets = sniff(count=5000, timeout=30)
        ml_detector.fit(sample_packets)
    except Exception as e:
        print(f"ML training error: {e}")
        print("Continuing with basic detection only")

    # Start worker thread
    worker_thread = threading.Thread(target=packet_worker, daemon=True)
    worker_thread.start()
    
    # Start packet capture in a background thread
    capture_thread = threading.Thread(target=capture_loop, daemon=True)
    capture_thread.start()

    try:
        # Run the Dash app in the main thread
        print("[*] Starting dashboard on http://localhost:8055")
        app.run(debug=False, port=8055, use_reloader=False)
    except KeyboardInterrupt:
        running = False
    finally:
        print("\n[*] Shutting down...")
        # Save captured packets
        if captured_packets:
            wrpcap("results/captured_traffic.pcap", captured_packets)
        print("[*] Capture stopped. Results saved.")

