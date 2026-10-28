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
    exts.extend(b'\x00\x2b\x00\x03\x02\x03\x04')

    groups = b'\x11\xec\x00\x1d\x00\x17'
    exts.extend(b'\x00\x0a' + (len(groups) + 2).to_bytes(2, 'big') + len(groups).to_bytes(2, 'big') + groups)

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
        print(f"[+] ĐÃ GỬI THÀNH CÔNG gói tin Hybrid PQC sang cổng {target_port}!")
    except Exception as e:
        print(f"[-] Lỗi kết nối tới cổng {target_port}: {e}")
    finally:
        s.close()

if __name__ == '__main__':
    send_pqc_client_hello()
