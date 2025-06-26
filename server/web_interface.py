from flask import Flask, render_template, jsonify, request
from message_analyzer import MessageAnalyzer
from datetime import datetime
import json
import os
import requests

# ANSI color codes
YELLOW = '\033[0;33m'
RESET = '\033[0m'

app = Flask(__name__)
analyzer = MessageAnalyzer()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analysis')
def get_analysis():
    return jsonify(analyzer.get_analysis())

@app.route('/api/recent-messages')
def get_recent_messages():
    messages = analyzer.get_recent_messages()
    # Convert datetime objects to strings for JSON serialization
    for msg in messages:
        if isinstance(msg['timestamp'], datetime):
            msg['timestamp'] = msg['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
    return jsonify(messages)

@app.route('/api/client-stats')
def get_client_stats():
    return jsonify(analyzer.get_client_statistics())

@app.route('/api/security-stats')
def get_security_stats():
    return jsonify(analyzer.get_security_statistics())

@app.route('/api/add-message', methods=['POST'])
def api_add_message():
    data = request.json
    client_address = data.get('client_address')
    message = data.get('message')
    if client_address and message:
        add_message(client_address, message)
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error', 'reason': 'Missing data'}), 400

@app.route('/api/disconnect-client', methods=['POST'])
def api_disconnect_client():
    data = request.json
    client_address = data.get('client_address')
    if client_address:
        analyzer.mark_disconnected(client_address)
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error', 'reason': 'Missing client_address'}), 400

@app.route('/api/add-connection', methods=['POST'])
def api_add_connection():
    data = request.json
    timestamp = data.get('timestamp')
    client_address = data.get('client_address')
    print(f"DEBUG: Received connection event at {timestamp} from {client_address}")
    if timestamp:
        analyzer.record_connection(datetime.fromisoformat(timestamp))
        if client_address:
            analyzer.db.save_connection_event(client_address, 'connect', datetime.fromisoformat(timestamp))
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'error', 'reason': 'Missing timestamp'}), 400

@app.route('/api/connection-stats')
def get_connection_stats():
    return jsonify(analyzer.get_connection_stats_per_hour())

def add_message(client_address: str, message: str):
    """Add a message to the analyzer."""
    analyzer.add_message(client_address, message, datetime.now())

if __name__ == '__main__':
    # Ensure the templates directory exists
    os.makedirs('templates', exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)

try:
    resp = requests.post(
        "http://localhost:5000/api/add-connection",
        json={"timestamp": datetime.now().isoformat()},
        timeout=1
    )
    print(f"DEBUG: POST /api/add-connection status: {resp.status_code}, response: {resp.text}")
except Exception as e:
    print(f"{YELLOW}Could not update connection stats: {e}{RESET}") 