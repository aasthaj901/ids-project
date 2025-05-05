from flask import Flask, render_template, redirect, url_for
from flask_socketio import SocketIO
from threading import Thread
import time
import os
import logging

from src.traffic_simulator import TrafficSimulator
from src.threat_intelligence import ThreatIntelligence
from src.ml_layer import MLLayer  # Import your ML layer
from src.dpi_layer import DPILayer  # Import the DPILayer

# Suppress Flask's default request logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)
socketio = SocketIO(app)
threat_intel = ThreatIntelligence()
traffic_simulator = TrafficSimulator(threat_intel)
ml_layer = MLLayer()  # Initialize your ML layer
dpi_layer = DPILayer()  # Initialize your DPI layer

LOG_FILE = 'traffic_simulation.log'

def tail_log():
    """Continuously tail the log file and stream relevant IDS logs to the client."""
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'w').close()

    with open(LOG_FILE, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                # Filter only IDS-related content
                keywords = ['Blocked', 'DPI', 'malicious', 'Suspicious', 'attack', 'detected']
                if any(keyword.lower() in line.lower() for keyword in keywords):
                    socketio.emit('log_update', {'log': line.strip()})
            time.sleep(0.5)

def emit_ml_stats():
    """Periodically send ML layer stats to the frontend."""
    while True:
        ml_stats = {
            'mlPackets': ml_layer.get_total_packets_analyzed(),
            'suspiciousTraffic': len(ml_layer.get_suspicious_ips())
        }
        socketio.emit('ml_update', ml_stats)
        time.sleep(2)  # Update every 2 seconds

def emit_dpi_logs():
    while True:
        if dpi_layer.detection_counts:
            dpi_summary = dpi_layer.generate_summary()
            dpi_stats = {
                'dpiPackets': dpi_layer.total_packets,  # you must maintain this
                'suspiciousTraffic': sum(dpi_layer.detection_counts.values())
            }
            socketio.emit('dpi_update', dpi_stats)
        time.sleep(2)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/simulate', methods=['POST'])
def simulate():
    traffic_simulator.generate_suspicious_traffic()
    return redirect(url_for('index'))

@socketio.on('connect')
def handle_connect():
    print('Client connected')

if __name__ == '__main__':
    threat_intel.update_threat_intelligence()
    thread = Thread(target=tail_log)
    thread.daemon = True
    thread.start()

    ml_thread = Thread(target=emit_ml_stats)
    ml_thread.daemon = True
    ml_thread.start()

    dpi_thread = Thread(target=emit_dpi_logs)
    dpi_thread.daemon = True
    dpi_thread.start()

    socketio.run(app, debug=True)
