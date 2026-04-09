import socket, struct

SERVER_IP   = "10.30.200.146"
SERVER_PORT = 5354

def is_valid_domain(domain):
    if not domain:
        return False
    if len(domain) > 253:
        return False
    if "." not in domain:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False
    if ".." in domain:
        return False
    if " " in domain:
        return False
    labels = domain.split(".")
    for label in labels:
        if not label:
            return False
        if len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        import re
        if not re.match(r'^[a-zA-Z0-9-]+$', label):
            return False
    return True

def build_query(domain):
    txid   = 0xAAAA
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    q      = b""
    for part in domain.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b'\x00' + struct.pack("!HH", 1, 1)
    return header + q

def parse_ip(data):
    try:
        ancount = (data[6] << 8) | data[7]
        if ancount == 0:
            return "Domain not found (NXDOMAIN)"

        # Skip header 12 bytes
        idx = 12

        # Skip question section
        while idx < len(data) and data[idx] != 0:
            idx += data[idx] + 1
        idx += 5  # skip zero + qtype + qclass

        # Parse answer section
        while idx < len(data):
            # Handle name pointer or label
            if (data[idx] & 0xC0) == 0xC0:
                idx += 2
            else:
                while idx < len(data) and data[idx] != 0:
                    idx += data[idx] + 1
                idx += 1

            if idx + 10 > len(data):
                break

            rtype    = (data[idx] << 8) | data[idx+1]
            idx += 2
            idx += 2   # skip class
            idx += 4   # skip TTL
            rdlength = (data[idx] << 8) | data[idx+1]
            idx += 2

            # Type 1 = A record = IPv4
            if rtype == 1 and rdlength == 4:
                return ".".join(str(data[idx+i]) for i in range(4))

            idx += rdlength

        return "No A record found"

    except Exception as e:
        return f"Parse error: {e}"

def query_dns(domain):
    # Validate domain on client side first
    if not is_valid_domain(domain):
        print(f"[INVALID] '{domain}' is not a valid domain name")
        print("-" * 40)
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        print(f"[CLIENT] Querying -> {domain}")
        sock.sendto(build_query(domain), (SERVER_IP, SERVER_PORT))
        data, _ = sock.recvfrom(512)
        ip = parse_ip(data)
        print(f"[RESULT] {domain} -> {ip}")
        print("-" * 40)
    except socket.timeout:
        print(f"[TIMEOUT] No response for {domain}")
        print("-" * 40)
    except Exception as e:
        print(f"[ERROR] {e}")
        print("-" * 40)
    finally:
        sock.close()

if __name__ == "__main__":
    print("=" * 40)
    print("  DNS CLIENT - TEAMMATE 1")
    print("=" * 40)
    print("Type a domain name to query")
    print("Type 'quit' to exit")
    print("=" * 40)

    while True:
        domain = input("\nEnter domain: ").strip()
        
        if domain.lower() == "quit":
            print("Goodbye!")
            break
        
        if not domain:
            print("Please enter a domain name")
            continue
        
        query_dns(domain)