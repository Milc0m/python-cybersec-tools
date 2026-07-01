import socket
import sys
from datetime import datetime
import time
# import threading
# from queue import Queue
import argparse

parser = argparse.ArgumentParser(
    description="Banner grabber for security audits and penetration testing.",
    epilog="Example usage: python3 banner-grabber.py scanme.nmap.org --port 80"
)

# Required target argument (IP address or domain name)
parser.add_argument(
    "target",
    help="Target host for scanning (IP address or domain name, e.g.: google.com)"
)

# Optional argument for scan mode
parser.add_argument(
    "-p", "--port",
    type=int,
    help="Port number to scan"
)

args = parser.parse_args()

# Variables from parsed arguments
target_host = args.target
target_port = args.port

try:
    target_ip = socket.gethostbyname(target_host)
except socket.gaierror:
    print(f"\n[-] Error: Could not resolve host '{target_host}'")
    sys.exit()


print("-" * 50)
print(f" Banner Grabber (v1.0)")
print(f"Target:  {target_host} ({target_ip})")
print(f"Port:    {target_port}")
print(f"Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("-" * 50)
start_time = time.time()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3.0)

try:
    s.connect((target_ip, target_port))

    if target_port in [80, 8080]:
        s.sendall(b"GET / HTTP/1.1\r\nHost: " +
                  target_host.encode() + b"\r\n\r\n")

    result = s.recv(1024)

    banner = result.decode('utf-8', errors='ignore').strip()
    print(f"[+] Banner received:\n{banner}")

except socket.timeout:
    print(f"[-] Error: Connection timed out.")
except Exception as e:
    print(f"[-] Error: Could not connect to port {target_port} ({e})")
finally:
    s.close()

end_time = time.time()

print("-" * 50)
print("Scanning completed.")
print(f"Time taken: {end_time - start_time:.2f} seconds")
print("-" * 50)
