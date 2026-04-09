import socket, struct, threading, time, statistics

SERVER_IP   = "10.30.200.146"   # change to server IP if different laptop
SERVER_PORT = 5354
results     = []
lock        = threading.Lock()

def build_query(domain):
    txid   = 0x1234
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    q      = b""
    for part in domain.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b'\x00' + struct.pack("!HH", 1, 1)
    return header + q

# Create ONE shared socket at top
shared_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
shared_sock.settimeout(5)

def single_query(domain):
    start = time.time()
    try:
        shared_sock.sendto(build_query(domain), (SERVER_IP, SERVER_PORT))
        data, _ = shared_sock.recvfrom(512)
        latency = (time.time() - start) * 1000
        with lock:
            results.append(latency)
    except socket.timeout:
        print(f"[TIMEOUT] Query timed out")
    except Exception as e:
        print(f"[ERROR] {e}")