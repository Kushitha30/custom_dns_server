import struct

def parse_dns_query(data):
    txid, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", data[:12])
    domain_parts = []
    idx = 12
    while data[idx] != 0:
        length = data[idx]
        idx += 1
        domain_parts.append(data[idx:idx+length].decode())
        idx += length
    idx += 1
    qtype, qclass = struct.unpack("!HH", data[idx:idx+4])
    domain = ".".join(domain_parts)
    return txid, domain, qtype

def encode_domain(domain):
    encoded = b""
    for part in domain.split("."):
        encoded += bytes([len(part)]) + part.encode()
    return encoded + b'\x00'

def build_dns_response(txid, domain, ip):
    header   = struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    question = encode_domain(domain) + struct.pack("!HH", 1, 1)
    answer   = b'\xc0\x0c'
    answer  += struct.pack("!HH", 1, 1)
    answer  += struct.pack("!I", 300)
    answer  += struct.pack("!H", 4)
    answer  += bytes(map(int, ip.split('.')))
    return header + question + answer

def build_nxdomain(txid, domain):
    header   = struct.pack("!HHHHHH", txid, 0x8183, 1, 0, 0, 0)
    question = encode_domain(domain) + struct.pack("!HH", 1, 1)
    return header + question