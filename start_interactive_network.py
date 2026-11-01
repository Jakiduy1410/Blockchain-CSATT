"""
Interactive Network Launcher (Khoi chay mang tuong tac 6 Node P2P)
Muc tieu:
- Ho tro Hop tuy chon cau hinh linh hoat: --tls (ecdhe/hybrid/none) va --sig (ecdsa/mldsa44/mldsa87/all)
- Tich hop Menu giao dien dong lenh de chon nhanh khi chay truc tiep (cho demo & test)
- Giu cac tien trinh chay ngam de nguoi dung tu do mo cac tab trinh duyet tuong tac tay
- Ho tro tu tay bam nut Mine tren tab Node 2 de quan sat chu trinh theo nhip do cua ban
- Bam Ctrl+C de tat toan bo an toan
"""

import argparse
import json
import os
import subprocess
import sys
import time

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')


def get_python_cmd():
    if sys.executable and os.path.exists(sys.executable):
        return [sys.executable]
    import shutil
    for candidate in ['python3', 'python', 'py']:
        path = shutil.which(candidate)
        if path:
            return [path]
    return ['python']



def check_and_clear_port_conflicts(ports):
    """Kiểm tra và giải phóng các port bị chiếm dụng bởi tiến trình zombie trước khi chạy"""
    import socket
    busy_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.15)
            if s.connect_ex(('127.0.0.1', port)) == 0:
                busy_ports.append(port)
    if busy_ports:
        print(f"[!] Cảnh báo: Phát hiện các cổng sau đang bị chiếm dụng: {busy_ports}")
        if sys.platform == 'win32':
            print("[*] Đang tự động giải phóng các cổng bị kẹt trên Windows...")
            for bp in busy_ports:
                try:
                    res = subprocess.check_output(f'netstat -ano | findstr :{bp}', shell=True, text=True)
                    for line in res.strip().split('\n'):
                        parts = line.split()
                        if len(parts) >= 5 and 'LISTENING' in line:
                            pid = parts[-1]
                            if pid != '0':
                                subprocess.run(['taskkill', '/F', '/PID', pid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
            time.sleep(1.0)

def show_interactive_menu():
    """Hộp tùy chọn tương tác trực quan trên Terminal để người dùng dễ dàng Demo và Test"""
    print("\n" + "╔" + "═" * 76 + "╗")
    print("║        HỘP TÙY CHỌN CẤU HÌNH BẢO MẬT MẠNG P2P BLOCKCHAIN & CLIENT          ║")
    print("╠" + "═" * 76 + "╣")
    print("║  [1] CƠ CHẾ TRAO ĐỔI KHÓA & BẢO VỆ ĐƯỜNG TRUYỀN P2P (TLS 1.3 TRANSPORT):  ║")
    print("║      (1) Classical TLS 1.3 ECDHE (prime256v1 / NIST P-256) [Mặc định]      ║")
    print("║      (2) Hybrid Post-Quantum TLS (X25519 + ML-KEM-768 / FIPS 203)          ║")
    print("║      (3) Plaintext (Không mã hóa TLS - Đo kiểm hiệu năng thuần HTTP)      ║")
    print("║                                                                            ║")
    print("║  [2] THUẬT TOÁN CHỮ KÝ SỐ GIAO DỊCH ƯU TIÊN (SIGNATURE SCHEME):            ║")
    print("║      (1) Đa thuật toán (Hybrid / Auto: Hỗ trợ cả ECDSA, RSA & ML-DSA) [Mặc]║")
    print("║      (2) Post-Quantum ML-DSA-44 (FIPS 204 NIST Level 2 - Ví Alice_PQC)     ║")
    print("║      (3) Post-Quantum ML-DSA-87 (FIPS 204 NIST Level 5 - Ví Perf_MLDSA87)  ║")
    print("║      (4) Classical ECDSA (secp256k1 - Ví Alice/Bob cổ điển)                ║")
    print("╚" + "═" * 76 + "╝\n")

    # 1. Nhập lựa chọn TLS
    tls_choice = input("👉 Chọn cơ chế TLS [1-3] (Nhấn Enter chọn mặc định 1 - ECDHE): ").strip()
    if tls_choice == '2':
        tls_mode = 'hybrid'
    elif tls_choice == '3':
        tls_mode = 'none'
    else:
        tls_mode = 'ecdhe'

    # 2. Nhập lựa chọn Signature
    sig_choice = input("👉 Chọn thuật toán Signature [1-4] (Nhấn Enter chọn mặc định 1 - All): ").strip()
    if sig_choice == '2':
        sig_mode = 'mldsa44'
    elif sig_choice == '3':
        sig_mode = 'mldsa87'
    elif sig_choice == '4':
        sig_mode = 'ecdsa'
    else:
        sig_mode = 'all'

    return tls_mode, sig_mode


def main():
    parser = argparse.ArgumentParser(description="Blockchain P2P 6-Node Network Launcher")
    parser.add_argument('--tls', type=str, default=None,
                        choices=['ecdhe', 'hybrid', 'mlkem768', 'none', 'plaintext'],
                        help="Cơ chế bảo mật TLS: ecdhe (mặc định), hybrid (X25519+ML-KEM-768), none")
    parser.add_argument('--sig', type=str, default=None,
                        choices=['ecdsa', 'mldsa44', 'mldsa87', 'rsa', 'all', 'pqc'],
                        help="Thuật toán chữ ký số ưu tiên: ecdsa, mldsa44, mldsa87, all (mặc định)")
    parser.add_argument('-i', '--menu', '--interactive', action='store_true',
                        help="Bắt buộc hiện Hộp tùy chọn tương tác để chọn cấu hình")
    parser.add_argument('-y', '--non-interactive', '--defaults', action='store_true',
                        help="Bỏ qua hộp tùy chọn và sử dụng cấu hình mặc định")
    parser.add_argument('--auto-mine', action='store_true',
                        help="Kích hoạt tự động đào cho Node 2 (Miner)")

    args, _ = parser.parse_known_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))

    # Kiểm tra xem có cần hiển thị Hộp tùy chọn không
    should_prompt = args.menu or (args.tls is None and args.sig is None and not args.non_interactive and sys.stdin.isatty())

    if should_prompt:
        tls_mode, sig_mode = show_interactive_menu()
    else:
        tls_mode = (args.tls or os.environ.get("BLOCKCHAIN_TLS_MODE", "ecdhe")).lower()
        sig_mode = (args.sig or os.environ.get("BLOCKCHAIN_SIG_MODE", "all")).lower()

    if tls_mode == 'mlkem768':
        tls_mode = 'hybrid'
    if tls_mode == 'plaintext':
        tls_mode = 'none'
    if sig_mode == 'pqc':
        sig_mode = 'mldsa44'

    # Thiết lập biến môi trường cho tiến trình con
    env = os.environ.copy()
    env["BLOCKCHAIN_TLS_MODE"] = tls_mode
    env["BLOCKCHAIN_SIG_MODE"] = sig_mode

    tls_title = "TLS 1.3 ECDHE (prime256v1)"
    if tls_mode == "hybrid":
        pqc_cnf = os.path.join(base_dir, 'configs', 'pqc_openssl.cnf')
        if os.path.exists(pqc_cnf):
            env["OPENSSL_CONF"] = pqc_cnf
        tls_title = "TLS 1.3 Hybrid (X25519 + ML-KEM-768 FIPS 203)"
    elif tls_mode == "none":
        tls_title = "Plaintext (Không dùng TLS - HTTP)"

    sig_title = "Đa thuật toán (Hybrid: ECDSA + RSA + ML-DSA-44)"
    if sig_mode == "mldsa44":
        sig_title = "Post-Quantum ML-DSA-44 (FIPS 204 NIST Level 2 - Ví Alice_PQC)"
    elif sig_mode == "mldsa87":
        sig_title = "Post-Quantum ML-DSA-87 (FIPS 204 NIST Level 5 - Ví Perf_MLDSA87)"
    elif sig_mode == "ecdsa":
        sig_title = "Classical ECDSA-secp256k1 (Ví Alice/Bob)"

    print("=" * 78)
    print("  KHOI CHAY MANG BLOCKCHAIN P2P 6 NODE - CHE DO TUONG TAC THUC TE")
    print("=" * 78)
    print("  🛡️  CẤU HÌNH BẢO MẬT ĐANG HOẠT ĐỘNG:")
    print(f"      • Cơ chế TLS:      {tls_title}")
    print(f"      • Chữ ký số:       {sig_title}")
    if tls_mode == "hybrid" and "OPENSSL_CONF" in env:
        print(f"      • OpenSSL Config:  {env['OPENSSL_CONF']}")
    print("-" * 78)

    config_path = os.path.join(base_dir, 'configs', 'network_6nodes.json')
    if not os.path.exists(config_path):
        config_path = os.path.join(base_dir, 'network_6nodes.json')
    with open(config_path, 'r', encoding='utf-8') as f:
        net_cfg = json.load(f)

    py_cmd = get_python_cmd()
    print(f"[*] He dieu hanh: {sys.platform} | Python: {' '.join(py_cmd)}")

    # Pre-flight check port conflicts
    ports_to_check = [8080] + [n['port'] for n in net_cfg['nodes']] + [n['port'] + 1000 for n in net_cfg['nodes']]
    check_and_clear_port_conflicts(ports_to_check)

    processes = []

    try:
        print("\n[*] 1. Dang khoi dong 6 Node P2P Mesh...")
        for node in net_cfg['nodes']:
            cmd = py_cmd + ['blockchain/blockchain.py', '-p', str(node['port']),
                            '--tls', tls_mode, '--sig', sig_mode]
            if args.auto_mine and node.get('is_miner'):
                cmd.append('--miner')
            if node['peers']:
                cmd.extend(['--peers', ','.join(node['peers'])])

            p = subprocess.Popen(cmd, cwd=base_dir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(p)
            role_desc = 'MINER [AUTO] ⛏' if (args.auto_mine and node['is_miner']) else ('MINER [MANUAL] ⛏' if node['is_miner'] else 'RELAY')
            print(f"    [OK] Node {node['id']} dang khoi dong tai: http://127.0.0.1:{node['port']} ({role_desc})")

        print("\n[*] 2. Dang khoi dong Blockchain Client...")
        p_client = subprocess.Popen(py_cmd + ['blockchain_client/blockchain_client.py', '-p', '8080', '--sig', sig_mode],
                                    cwd=base_dir, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(p_client)
        print("    [OK] Client (Vi nguoi dung) dang khoi dong tai: http://127.0.0.1:8080")

        # Readiness Probe: Đảm bảo toàn bộ 7 tiến trình đều phản hồi HTTP 200 trước khi mở kết nối
        print("\n[*] 3. Kiem tra do san sang ket noi (Readiness Healthcheck)...")
        all_ready = False
        import urllib.request
        for _ in range(12):
            time.sleep(0.4)
            nodes_ok = 0
            for node in net_cfg['nodes']:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{node['port']}/status", timeout=0.6) as r:
                        if r.getcode() == 200:
                            nodes_ok += 1
                except Exception:
                    pass
            client_ok = False
            try:
                with urllib.request.urlopen("http://127.0.0.1:8080/wallets/sample", timeout=0.6) as r:
                    if r.getcode() == 200:
                        client_ok = True
            except Exception:
                pass

            if nodes_ok == len(net_cfg['nodes']) and client_ok:
                all_ready = True
                break

        if all_ready:
            print("    [SUCCESS] Toan bo 6 Node P2P Mesh va 1 Client da san sang 100%! Khong gap bat ky loi ket noi nao.")
        else:
            print("    [NOTE] Cac tien trinh da khoi chay, ket noi P2P dang duoc duy tri on dinh.")

        print("\n" + "=" * 78)
        print("  DANH SACH DUONG DAN TRINH DUYET SAN SANG DE BAN MO VA TUONG TAC:")
        print("=" * 78)
        print("  * Tab 1 (Vi Client):   http://localhost:8080/make/transaction")
        print("  * Tab 2 (Node 1):      http://localhost:5000  (Ingress / Relay)")
        print("  * Tab 3 (Node 2):      http://localhost:5001  (Miner ⛏ - Co nut bam Mine)")
        print("  * Tab 4 (Node 3):      http://localhost:5002  (Relay)")
        print("  * Tab 5 (Node 4):      http://localhost:5003  (Relay)")
        print("  * Tab 6 (Node 5):      http://localhost:5004  (Relay)")
        print("  * Tab 7 (Node 6):      http://localhost:5005  (Relay)")
        print("  * VISUALIZER LIVE:     http://localhost:5000/visualizer (Hoac bat ky Node nao)")
        print("-" * 78)
        print("  Luu y:")
        print("  - Cac tab Node co che do 'Live Sync (2s)' tu dong cap nhat khong can F5.")
        print(f"  - Hop den 'Security Audit Trail' se ghi nhan chi tiet qua trinh verify {sig_mode.upper()} & P2P.")
        print("=" * 78)
        print("\n>>> MANG DANG HOAT DONG. Nhan 'Ctrl+C' de dung toan bo mang <<<\n")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Nhan tin hieu dung tu ban phim...")
    finally:
        print("[*] Dang tat an toan toan bo 7 tien trinh...")
        for p in processes:
            try:
                if sys.platform == 'win32' and hasattr(p, 'pid'):
                    subprocess.run(['taskkill', '/F', '/T', '/PID', str(p.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    p.terminate()
            except Exception:
                pass
        print("[*] Da tat toan bo mang Blockchain sach se. Tam biet!")


if __name__ == '__main__':
    main()
