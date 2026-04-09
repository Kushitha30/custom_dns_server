import socket

UPSTREAM_DNS  = "8.8.8.8"
UPSTREAM_PORT = 53
TIMEOUT       = 3

def forward_to_upstream(query_data):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(TIMEOUT)
            s.sendto(query_data, (UPSTREAM_DNS, UPSTREAM_PORT))
            response, _ = s.recvfrom(512)
            print(f"[FORWARDER] Got response from 8.8.8.8")
            return response
    except socket.timeout:
        print("[FORWARDER] Upstream timed out")
        return None
    except Exception as e:
        print(f"[FORWARDER ERROR] {e}")
        return None