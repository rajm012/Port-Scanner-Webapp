from flask import Flask, render_template, request, jsonify
from app import app
from app.scanner import scan_ports, shodan_lookup, get_ttl, detect_os, geoip_lookup
import threading

scanning = False
scanning_lock = threading.Lock()

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
    return jsonify(results)

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
