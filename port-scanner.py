import socket
import sys
from datetime import datetime
import threading
from queue import Queue
import argparse

print_lock = threading.Lock()

parser = argparse.ArgumentParser(
    description="Own port scanner for security audits and penetration testing.",
    epilog="Example usage: python3 scanner.py scanme.nmap.org --mode all --threads 500"
)

# Required target argument (IP address or domain name)
parser.add_argument(
    "target",
    help="Target host for scanning (IP address or domain name, e.g.: google.com)"
)

# Optional argument for scan mode
parser.add_argument(
    "-m", "--mode",
    choices=["top", "all"],
    default="top",
    help="Scan mode: 'top' (critical standard ports) or 'all' (all ports from 1 to 65535). Default: top"
)

# Optional argument for number of threads
parser.add_argument(
    "-t", "--threads",
    type=int,
    default=100,
    help="Number of concurrent threads for scanning. Default: 100"
)

# Arguments parsing
args = parser.parse_args()

# Variables from parsed arguments
target_host = args.target
scan_mode = args.mode
threads_count = args.threads

# Critical ports for the --mode top
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
    1433, 3306, 3389, 5900, 8080, 8443
]

try:
    target_ip = socket.gethostbyname(target_host)
except socket.gaierror:
    print(f"\n[-] Error: Could not resolve host '{target_host}'")
    sys.exit()

print("-" * 50)
print(f" PORT SCANNER (v1.0)")
print(f"Target:  {target_host} ({target_ip})")
print(f"Mode:    {scan_mode}")
print(f"Threads: {threads_count}")
print(f"Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("-" * 50)

# 2. Queue of ports
q = Queue()

if scan_mode == "all":
    print("[*] Loading all 65535 ports into the queue... Please wait.")
    for port in range(1, 65536):
        q.put(port)
else:
    for port in TOP_PORTS:
        q.put(port)

# 3. Worker function


def port_scan_worker():
    while not q.empty():
        port = q.get()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)

        result = s.connect_ex((target_ip, port))

        if result == 0:
            with print_lock:
                print(f"[+] Port {port:<5}: OPEN")

        s.close()
        q.task_done()


# 4. Starting threads
for _ in range(threads_count):
    thread = threading.Thread(target=port_scan_worker)
    thread.daemon = True
    thread.start()

q.join()

print("-" * 50)
print("Scanning completed.")
print("-" * 50)
