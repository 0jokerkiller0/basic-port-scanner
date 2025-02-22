import os
import sys

# ✅ Check and install 'tqdm' automatically
try:
    from tqdm import tqdm
except ImportError:
    print("📌 'tqdm' not found! Installing now...")
    os.system(f"{sys.executable} -m pip install tqdm")
    from tqdm import tqdm  # Import again after installation

import socket
import threading
from datetime import datetime

# Common ports and vulnerable ports lists
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP Proxy", 5900: "VNC"
}

VULNERABLE_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 135: "RPC", 139: "NetBIOS", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP"
}

def scan_port(ip, port, open_ports, progress):
    """Attempts to connect to a port and identify the service."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Set timeout to 500ms
            result = s.connect_ex((ip, port))
            if result == 0:
                service = COMMON_PORTS.get(port, VULNERABLE_PORTS.get(port, "Unknown"))
                print(f"[+] Port {port} is OPEN ({service})")
                open_ports.append((port, service))
    except Exception:
        pass
    finally:
        progress.update(1)

def resolve_host(target):
    """Resolves a domain to an IP address if needed."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print("❌ Unable to resolve target!")
        return None

def scan_ports(target, scan_type):
    """Scans ports based on selected scan type."""
    ip = resolve_host(target)
    if not ip:
        return

    if scan_type == "1":
        ports = range(1, 65536)
        print(f"\n🔍 Performing Full Scan (1-65535) on {target} ({ip})...\n")
    elif scan_type == "2":
        ports = COMMON_PORTS.keys()
        print(f"\n🔍 Scanning Common Ports on {target} ({ip})...\n")
    elif scan_type == "3":
        ports = VULNERABLE_PORTS.keys()
        print(f"\n⚠️ Scanning Most Vulnerable Ports on {target} ({ip})...\n")
    else:
        print("❌ Invalid selection. Exiting.")
        return

    open_ports = []
    threads = []

    # Progress bar setup
    with tqdm(total=len(ports), desc="Scanning Progress", unit="port") as progress:
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(ip, port, open_ports, progress))
            threads.append(thread)
            thread.start()

            if len(threads) >= 500:
                for thread in threads:
                    thread.join()
                threads = []

        for thread in threads:
            thread.join()

    # Save results to a file
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("scan_results.txt", "a") as file:
        file.write(f"Scan Results for {target} ({ip}) - {timestamp}:\n")
        for port, service in open_ports:
            file.write(f"Port {port} is OPEN ({service})\n")
        file.write("\n")

    if open_ports:
        print("\n✅ Scan complete! Open ports saved in 'scan_results.txt'.")
    else:
        print("\n❌ No open ports found.")

# User input
print("\nSelect Scan Type:")
print("1️⃣ Full Scan (All 65,535 ports)")
print("2️⃣ Common Ports Scan (e.g., HTTP, SSH, FTP, DNS)")
print("3️⃣ Most Vulnerable Ports Scan (Often attacked ports)")
scan_choice = input("\nEnter choice (1/2/3): ")

target = input("Enter target domain or IP address: ")
scan_ports(target, scan_choice)
