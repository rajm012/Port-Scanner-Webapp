import socket
import threading
import concurrent.futures
import os
import shodan
import struct
import time
import requests

# Replace with your Shodan API key
SHODAN_API_KEY = "enter-own-api-key"

# Common services mapping
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 3389: "RDP", 5000: "Flask Server"
}


def get_service(port):
    """Try to get the service name using known mappings or socket."""
    try:
        return COMMON_SERVICES.get(port, socket.getservbyport(port, "tcp"))
    except (OSError, socket.error):
        return "Unknown"


def banner_grab(ip, port):
    """Attempts to grab the banner of an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
        response = sock.recv(1024).decode(errors="ignore")
        sock.close()

        if "Server:" in response:
            return response.split("\n")[0]
        return response[:50]
    except:
        return "Unknown"


def scan_tcp_port(target_ip, port, progress_callback):
    """Scan a single TCP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))

        if result == 0:
            service = get_service(port)
            if service == "Unknown":
                service = banner_grab(target_ip, port)
            sock.close()
            progress_callback(port, "Open", service)
        else:
            progress_callback(port, "Closed", "N/A")
    except Exception as e:
        progress_callback(port, "Error", str(e))


def scan_udp_port(target_ip, port, progress_callback):
    """Scan a single UDP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10)  # Increase timeout for UDP
        sock.sendto(b"\x00", (target_ip, port))  # Send empty UDP packet

        try:
            data, _ = sock.recvfrom(1024)
            progress_callback(port, "Open", "UDP Response Received")

        except socket.timeout:
            sock.sendto(b"\x00", (target_ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                progress_callback(port, "Open", "UDP Response Received")

            except socket.timeout:
                progress_callback(port, "Filtered", "No Response")

    except Exception as e:
        if "10054" in str(e):
            progress_callback(port, "Error", "Connection forcibly closed by remote host")
        else:
            progress_callback(port, "Error", str(e))

    finally:
        sock.close()


def scan_ports(target_ip, port_range, progress_callback, scan_type="tcp"):
    """Scan ports using ThreadPoolExecutor."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for port in port_range:
            if scan_type == "tcp":
                futures.append(executor.submit(scan_tcp_port, target_ip, port, progress_callback))
            elif scan_type == "udp":
                futures.append(executor.submit(scan_udp_port, target_ip, port, progress_callback))

        for future in concurrent.futures.as_completed(futures):
            future.result()


def shodan_lookup(ip):
    """Query Shodan for additional information about the target IP."""
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        info = api.host(ip)

        result = {
            "IP": info.get("ip_str", "Unknown"),
            "Organization": info.get("org", "Unknown"),
            "ISP": info.get("isp", "Unknown"),
            "OS": info.get("os", "Unknown"),
            "Open Ports": info.get("ports", []),
            "Vulnerabilities": info.get("vulns", "None"),
        }

        return result

    except shodan.APIError as e:
        return {"Error": f"Shodan API Error: {e}"}


def detect_os(ttl):
    """Detect OS based on TTL value."""
    if ttl > 128:
        return "Cisco Device (TTL > 128)"
    elif 113 < ttl <= 128:
        return "Windows (TTL ~128)"
    elif 64 <= ttl <= 113:
        return "Linux/Unix (TTL ~64)"
    elif ttl < 64:
        return "BSD/MacOS (TTL < 64)"
    else:
        return "Unknown"


def get_ttl(target_ip):
    """Get the TTL value from an ICMP ping."""
    try:
        # Create a raw socket for ICMP
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(3)

        # ICMP Echo Request (Type 8, Code 0)
        icmp_header = struct.pack("!BBHHH", 8, 0, 0, os.getpid() & 0xFFFF, 1)

        # Calculate checksum
        checksum = 0
        for i in range(0, len(icmp_header), 2):
            checksum += (icmp_header[i] << 8) + icmp_header[i + 1]
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF

        # Repack the header with the correct checksum
        icmp_header = struct.pack("!BBHHH", 8, 0, checksum, os.getpid() & 0xFFFF, 1)

        # Send the ICMP packet
        sock.sendto(icmp_header, (target_ip, 1))

        # Wait for the response
        start_time = time.time()
        while time.time() - start_time < 2:  # Wait for up to 2 seconds
            try:
                response, _ = sock.recvfrom(1024)
                ttl = struct.unpack("!B", response[8:9])[0]  # Extract TTL from the IP header
                sock.close()
                return ttl
            except socket.timeout:
                continue

        sock.close()
        return None

    except Exception as e:
        print(f"Error in get_ttl: {e}")
        return None


def geoip_lookup(ip):
    """Perform a GeoIP lookup using ipinfo.io."""
    try:
        response = requests.get(f"http://ipinfo.io/{ip}/json")
        data = response.json()
        return {
            "IP": data.get("ip"),
            "City": data.get("city"),
            "Region": data.get("region"),
            "Country": data.get("country"),
            "ISP": data.get("org"),
        }
    except Exception as e:
        return {"Error": str(e)}