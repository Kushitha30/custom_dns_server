import threading

_lock = threading.Lock()

DNS_RECORDS = {
    "example.local":    "192.168.1.10",
    "mail.local":       "192.168.1.20",
    "web.local":        "192.168.1.30",
    "api.local":        "192.168.1.40",
    "db.local":         "192.168.1.50",
    "teamserver.local": "192.168.1.100",
}

def resolve_local(domain):
    with _lock:
        return DNS_RECORDS.get(domain.lower().rstrip("."), None)

def add_record(domain, ip):
    with _lock:
        DNS_RECORDS[domain.lower()] = ip
        print(f"[RECORDS] Added {domain} -> {ip}")

def delete_record(domain):
    with _lock:
        removed = DNS_RECORDS.pop(domain.lower(), None)
        if removed:
            print(f"[RECORDS] Deleted {domain}")
        else:
            print(f"[RECORDS] {domain} not found")

def list_records():
    with _lock:
        return dict(DNS_RECORDS)