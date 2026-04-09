import socket, ssl, threading, json
from records import add_record, delete_record, list_records

def handle_admin_client(conn, addr):
    try:
        print(f"[SSL ADMIN] Connection from {addr}")
        data  = conn.recv(4096).decode().strip()
        cmd   = json.loads(data)

        if cmd["action"] == "add":
            add_record(cmd["domain"], cmd["ip"])
            reply = {"status": "ok", "msg": f"Added {cmd['domain']}"}

        elif cmd["action"] == "delete":
            delete_record(cmd["domain"])
            reply = {"status": "ok", "msg": f"Deleted {cmd['domain']}"}

        elif cmd["action"] == "list":
            reply = {"status": "ok", "records": list_records()}

        else:
            reply = {"status": "error", "msg": "Unknown action"}

        conn.send(json.dumps(reply).encode())

    except Exception as e:
        print(f"[SSL ADMIN ERROR] {e}")
    finally:
        conn.close()

def start_ssl_control(port=8443):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    # Server certificate
    context.load_cert_chain(
        "../certs/server.crt",
        "../certs/server.key"
    )
    
    # Tell server to verify client certificate
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations("../certs/client.crt")

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(("0.0.0.0", port))
    raw.listen(5)

    with context.wrap_socket(raw, server_side=True) as ssock:
        print(f"[SSL ADMIN] Listening on TCP port 8443")
        print(f"[SSL ADMIN] Client authentication enabled")
        while True:
            try:
                conn, addr = ssock.accept()
                # Print client certificate details
                cert = conn.getpeercert()
                print(f"[SSL AUTH] Client verified: {cert}")
                t = threading.Thread(
                    target=handle_admin_client,
                    args=(conn, addr)
                )
                t.daemon = True
                t.start()
            except ssl.SSLError as e:
                print(f"[SSL ERROR] Client auth failed: {e}")
            except Exception as e:
                print(f"[SSL ERROR] {e}")