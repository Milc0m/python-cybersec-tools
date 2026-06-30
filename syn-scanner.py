from scapy.all import IP, TCP, RandShort, sr1, send
import socket
import sys
from datetime import datetime
import time
import threading
from queue import Queue
import argparse

print_lock = threading.Lock()

parser = argparse.ArgumentParser(
    description="Silent port scanner for security audits and penetration testing.",
    epilog="Example usage: sudo python3 syn-scanner.py scanme.nmap.org --mode all --threads 500"
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

parser.add_argument(
    "--show-closed",
    action="store_true",
    help="Show closed ports in the output. By default, they are hidden."
)

# Arguments parsing
args = parser.parse_args()

# Variables from parsed arguments
target_host = args.target
scan_mode = args.mode
threads_count = args.threads
show_closed = args.show_closed
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
print(f" SILENT PORT SCANNER (v1.0)")
print(f"Target:  {target_host} ({target_ip})")
print(f"Mode:    {scan_mode}")
print(f"Threads: {threads_count}")
print(f"Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("-" * 50)
start_time = time.time()

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
        packet = IP(dst=target_ip) / TCP(sport=RandShort(),
                                         dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=False)

        if response is None:
            if show_closed:
                with print_lock:
                    print(
                        f"[-] Port {port}: FILTERED (Host did not respond, possibly due to a firewall)")
        elif response.haslayer(TCP):
            if response[TCP].flags == "SA":
                with print_lock:
                    print(f"[+] Port {port}: OPEN (Received SYN-ACK)")

                rst_packet = IP(dst=target_ip) / \
                    TCP(sport=packet[TCP].sport, dport=port, flags="R")
                send(rst_packet, verbose=False)

            elif response[TCP].flags == "RA":
                if show_closed:
                    with print_lock:
                        print(f"[-] Port {port}: CLOSED (Received RST-ACK)")

        q.task_done()


git for _ in range(threads_count):
    thread = threading.Thread(target=port_scan_worker)
    thread.daemon = True
    thread.start()

q.join()

end_time = time.time()

print("-" * 50)
print("Scanning completed.")
print(f"Time taken: {end_time - start_time:.2f} seconds")
print("-" * 50)
