import socket
import os
import sys
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def send_pqc_client_hello():
    # Nhận cổng truyền vào từ dòng lệnh, mặc định là 6000
    target_port = int(sys.argv[1]) if len(sys.argv) > 1 else 6000
    target_host = "127.0.0.1"

    client_random = os.urandom(32)
    session_id = os.urandom(32)
    cipher_suites = b'\x13\x01\x13\x02\x13\x03'
    cipher_block = len(cipher_suites).to_bytes(2, 'big') + cipher_suites
    comp_block = b'\x01\x00'

    exts = bytearray()
    # 1. Extension: supported_versions (TLS 1.3)
    exts.extend(b'\x00\x2b\x00\x03\x02\x03\x04')

    # 2. Extension: supported_groups (Chứa X25519MLKEM768 0x11ec)
    groups = b'\x11\xec\x00\x1d\x00\x17'
    exts.extend(b'\x00\x0a' + (len(groups) + 2).to_bytes(2, 'big') + len(groups).to_bytes(2, 'big') + groups)

    # 3. Extension: signature_algorithms (RFC 8446 Signature Schemes)
    sigalgs = b'\x04\x03\x08\x04\x04\x01\x05\x01\x06\x01\x02\x01'
    exts.extend(b'\x00\x0d' + (len(sigalgs) + 2).to_bytes(2, 'big') + len(sigalgs).to_bytes(2, 'big') + sigalgs)

    # 4. Extension: key_share (ML-KEM-768 Key Share 1216 bytes)
    pqc_key_share = os.urandom(1216)
    entry = b'\x11\xec' + len(pqc_key_share).to_bytes(2, 'big') + pqc_key_share
    shares_list = len(entry).to_bytes(2, 'big') + entry
    exts.extend(b'\x00\x33' + len(shares_list).to_bytes(2, 'big') + shares_list)

    exts_block = len(exts).to_bytes(2, 'big') + bytes(exts)
    ch_body = bytearray(b'\x03\x03' + client_random + len(session_id).to_bytes(1, 'big') + session_id + cipher_block + comp_block + exts_block)
    handshake_msg = b'\x01' + len(ch_body).to_bytes(3, 'big') + bytes(ch_body)
    tls_record = b'\x16\x03\x01' + len(handshake_msg).to_bytes(2, 'big') + handshake_msg

    print(f"[*] Đang gửi gói tin TLS 1.3 Client Hello chứa Hybrid X25519+ML-KEM (1216 bytes) tới cổng {target_port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((target_host, target_port))
        s.sendall(tls_record)
        time.sleep(0.5)
        # Nhận phản hồi từ Server (ServerHello hoặc Fatal Alert Handshake Failure)
        s.settimeout(2.0)
        try:
            resp = s.recv(4096)
            if resp:
                if len(resp) >= 7 and resp[0] == 0x15:
                    alert_desc = resp[6] if len(resp) > 6 else resp[-1]
                    print(f"[!] Server phản hồi TLS Alert (Level={resp[5]}, Description={alert_desc}): TỪ CHỐI BẮT TAY / FAIL-CLOSED!")
                elif len(resp) >= 6 and resp[0] == 0x16:
                    print(f"[+] Server chấp nhận và phản hồi ServerHello (len={len(resp)})!")
        except Exception:
            print("[*] Kết nối đã bị Server đóng ngắt chủ động (DROP_CONNECTION).")
        print(f"[+] ĐÃ GỬI THÀNH CÔNG gói tin Hybrid PQC sang cổng {target_port}!")
    except Exception as e:
        print(f"[-] Lỗi kết nối tới cổng {target_port}: {e}")
    finally:
        s.close()

if __name__ == '__main__':
    send_pqc_client_hello()
