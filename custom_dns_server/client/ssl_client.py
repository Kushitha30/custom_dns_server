import socket, ssl, json

SERVER_IP  = "127.0.0.1"
ADMIN_PORT = 8443

def send_command(action, domain=None, ip=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    
    # Client presents its own certificate to server
    context.load_cert_chain(
        "../certs/client.crt",
        "../certs/client.key"
    )
    
    # Client verifies server certificate
    context.load_verify_locations("../certs/server.crt")
    context.check_hostname = False
    context.verify_mode    = ssl.CERT_REQUIRED  # Changed from CERT_NONE

    try:
        with socket.create_connection((SERVER_IP, ADMIN_PORT)) as raw:
            with context.wrap_socket(raw) as ssock:
                # Show encryption details
                cipher = ssock.cipher()
                print(f"[SSL] Connected using {cipher[0]}")
                print(f"[SSL] Protocol: {ssock.version()}")

                cmd = {"action": action}
                if domain: cmd["domain"] = domain
                if ip:     cmd["ip"]     = ip

                ssock.send(json.dumps(cmd).encode())
                response = json.loads(ssock.recv(4096).decode())
                print(f"\n[ACTION]   {action.upper()}")
                print(f"[RESPONSE] {json.dumps(response, indent=2)}")
                print("-" * 40)
    except ssl.SSLError as e:
        print(f"[SSL ERROR] Authentication failed: {e}")
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    print("=" * 40)
    print("  SSL ADMIN CLIENT - TEAMMATE 2")
    print("=" * 40)
    send_command("list")
    send_command("add", domain="newsite.local", ip="192.168.1.200")
    send_command("list")
    send_command("delete", domain="newsite.local")
    send_command("list")