from scapy.all import IP, ICMP, sr1, arping
import ipaddress
from datetime import datetime
import time
import threading
from queue import Queue
import argparse

print_lock = threading.Lock()

parser = argparse.ArgumentParser(
    description="ICMP net scanner for security audits and penetration testing.",
    epilog="Example usage: sudo python3 net-scanner.py 192.168.1.1"
)

# Required target argument (IP address or domain name)
parser.add_argument(
    "target",
    help="Target network range (e.g., 192.168.1.0/24)"
)

parser.add_argument(
    "-m", "--mode",
    choices=["icmp", "arp"],
    default="icmp",
    help="Scan mode: 'icmp' (Ping) or 'arp' (ARP request). Default: icmp"
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
target_range = args.target
threads_count = args.threads
scan_mode = args.mode

print("-" * 50)
print(f" ICMP NET SCANNER (v1.0)")
print(f"Target:  {target_range}")
print(f"Mode:    {scan_mode}")
print(f"Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("-" * 50)
start_time = time.time()

if scan_mode == "arp":
    arping(target_range)
else:
    q = Queue()

    network = ipaddress.ip_network(target_range, strict=False)

    for ip in network.hosts():
        q.put(str(ip))

    def net_scan_worker():
        while not q.empty():
            addr = q.get()
            packet = IP(dst=addr) / ICMP()
            response = sr1(packet, timeout=1, verbose=False)

            if response and response.haslayer(ICMP):
                if response[ICMP].type == 0:
                    with print_lock:
                        print(f"[+] Host {addr} is alive!")
            q.task_done()

    for _ in range(threads_count):
        thread = threading.Thread(target=net_scan_worker)
        thread.daemon = True
        thread.start()

    q.join()


end_time = time.time()

print("-" * 50)
print("Scanning completed.")
print(f"Time taken: {end_time - start_time:.2f} seconds")
print("-" * 50)
