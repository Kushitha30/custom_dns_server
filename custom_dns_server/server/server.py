import socket
import threading
import sys
import os
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(__file__))

from dns_parser  import parse_dns_query, build_dns_response, build_nxdomain
from records     import resolve_local
from forwarder   import forward_to_upstream
from ssl_control import start_ssl_control

DNS_PORT = 5354
import time

# Simple cache dictionary
# stores domain -> (ip, timestamp)
DNS_CACHE = {}
CACHE_TTL = 300  # cache for 300 seconds

def get_from_cache(domain):
    if domain in DNS_CACHE:
        ip, timestamp = DNS_CACHE[domain]
        # Check if cache is still valid
        if time.time() - timestamp < CACHE_TTL:
            print(f"[CACHE HIT] {domain} -> {ip}")
            return ip
        else:
            # Cache expired remove it
            del DNS_CACHE[domain]
            print(f"[CACHE EXPIRED] {domain}")
    return None

def save_to_cache(domain, ip):
    DNS_CACHE[domain] = (ip, time.time())
    print(f"[CACHE SAVED] {domain} -> {ip}")

def handle_query(data, addr, sock):
    try:
        if len(data) < 12:
            print(f"[INVALID] Packet too short from {addr}")
            return

        txid, domain, qtype = parse_dns_query(data)

        if not domain or len(domain) > 253:
            print(f"[INVALID] Bad domain from {addr}")
            return

        print(f"\n[QUERY]   From {addr[0]}:{addr[1]} -> '{domain}'")

        # Step 1 - check cache first
        ip = get_from_cache(domain)

        if ip:
            # Cache hit - fastest response
            response = build_dns_response(txid, domain, ip)

        else:
            # Step 2 - check local records
            ip = resolve_local(domain)

            if ip:
                print(f"[LOCAL]   {domain} -> {ip}")
                save_to_cache(domain, ip)
                response = build_dns_response(txid, domain, ip)

            else:
                # Step 3 - forward to 8.8.8.8
                print(f"[FORWARD] {domain} -> asking 8.8.8.8")
                response = forward_to_upstream(data)

                if not response:
                    print(f"[NXDOMAIN] Could not resolve {domain}")
                    response = build_nxdomain(txid, domain)
                else:
                    # Cache the forwarded result
                    save_to_cache(domain, ip)

        sock.sendto(response, addr)

    except Exception as e:
        print(f"[ERROR] {e}")
def start_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(("0.0.0.0", DNS_PORT))
    except OSError as e:
        print(f"[ERROR] Port {DNS_PORT} in use!")
        sys.exit(1)

    print("=" * 45)
    print("   DNS SERVER STARTED")
    print(f"   UDP  port : {DNS_PORT}")
    print(f"   SSL  port : 8443")
    print(f"   Upstream  : 8.8.8.8")
    print(f"   Cache TTL : 300 seconds")
    print("=" * 45)

    # Thread pool of 50 workers
    # reuses threads instead of creating new ones
    executor = ThreadPoolExecutor(max_workers=50)

    while True:
        try:
            data, addr = sock.recvfrom(512)
            # Submit to thread pool instead of new thread
            executor.submit(handle_query, data, addr, sock)
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
            executor.shutdown(wait=False)
            break
        except Exception as e:
            print(f"[SERVER ERROR] {e}")