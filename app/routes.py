from flask import Flask, render_template, request, jsonify, send_file
from app import app
from app.scanner import scan_ports, shodan_lookup, get_ttl, detect_os, geoip_lookup
import threading
import json
import os
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)

scanning = False
scanning_lock = threading.Lock()

SCAN_RESULTS_FILE = os.path.join(os.path.dirname("E:\\4th Semester\\Port-Scanner-Webapp"), "scan_results.json")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    global scanning
    with scanning_lock:
        scanning = True

    target_ip = request.form.get('target_ip')
    start_port = int(request.form.get('start_port'))
    end_port = int(request.form.get('end_port'))
    scan_type = request.form.get('scan_type')

    if not target_ip:
        return jsonify({"error": "Please enter a target IP address."}), 400

    port_range = range(start_port, end_port + 1)
    results = []

    def progress_callback(port, status, service):
        results.append({"port": port, "status": status, "service": service})

    scan_ports(target_ip, port_range, progress_callback, scan_type)

    with open(SCAN_RESULTS_FILE, "w") as f:
        json.dump(results, f, indent=4)

    return jsonify(results)


@app.route('/download_results', methods=['GET'])
def download_results():
    """Endpoint to download the scan results as a JSON file."""

    if not os.path.exists(SCAN_RESULTS_FILE):
        logging.error(f"File {SCAN_RESULTS_FILE} not found.")
        return jsonify({"error": "No scan results found. Please run a scan first."}), 404

    try:
        return send_file(SCAN_RESULTS_FILE, as_attachment=True, mimetype="application/json", download_name="scan_results.json")
    
    except Exception as e:
        logging.error(f"Error sending file: {e}")
        return jsonify({"error": "Failed to download results."}), 500


@app.route('/shodan', methods=['POST'])
def shodan():
    data = request.get_json()
    if not data or 'target_ip' not in data:
        return jsonify({"error": "Missing target IP address."}), 400

    target_ip = data['target_ip']
    result = shodan_lookup(target_ip)
    return jsonify(result)

@app.route('/geoip', methods=['POST'])
def geoip():
    data = request.get_json()
    if not data or 'target_ip' not in data:
        return jsonify({"error": "Missing target IP address."}), 400

    target_ip = data['target_ip']
    result = geoip_lookup(target_ip)
    return jsonify(result)

@app.route('/os_detection', methods=['POST'])
def os_detection():
    data = request.get_json()
    if not data or 'target_ip' not in data:
        return jsonify({"error": "Missing target IP address."}), 400

    target_ip = data['target_ip']
    ttl = get_ttl(target_ip)
    if ttl is None:
        return jsonify({"error": "Could not determine OS. Ensure the target IP is reachable."}), 400

    os_guess = detect_os(ttl)
    return jsonify({"os": os_guess, "ttl": ttl})


@app.route('/help')
def help():
    return render_template('help.html')
