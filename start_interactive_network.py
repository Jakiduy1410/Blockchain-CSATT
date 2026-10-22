"""
Interactive Network Launcher (Khoi chay mang tuong tac 6 Node P2P)
Muc tieu:
- Giu cac tien trinh chay ngam de nguoi dung tu do mo cac tab trinh duyet tuong tac tay
- Ho tro tu tay bam nut Mine tren tab Node 2 de quan sat chu trinh theo nhip do cua ban
- Tu dong giai phong cac port 5000-5005, 8080 neu bi chiem boi tien trinh cu
- Bam Ctrl+C de tat toan bo an toan
"""

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


def cleanup_ports(ports):
    """Tu dong kiem tra va giai phong cac cong bi chiem dung truoc khi chay."""
    for port in ports:
        try:
            out = subprocess.check_output(f'netstat -ano | findstr :{port}', shell=True).decode('utf-8', errors='ignore')
            for line in out.strip().splitlines():
                parts = line.split()
                if len(parts) >= 5 and 'LISTENING' in parts:
                    pid = parts[-1]
                    if pid != str(os.getpid()):
                        subprocess.run(f'taskkill /F /PID {pid}', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass


def main():
    print("=" * 75)
    print("  KHOI CHAY MANG BLOCKCHAIN P2P 6 NODE - CHE DO TUONG TAC THUC TE")
    print("=" * 75)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(base_dir, 'configs', 'network_6nodes.json')
    if not os.path.exists(config_path):
        config_path = os.path.join(base_dir, 'network_6nodes.json')
    with open(config_path, 'r', encoding='utf-8') as f:
        net_cfg = json.load(f)

    py_cmd = get_python_cmd()
    print(f"[*] He dieu hanh: {sys.platform} | Python: {' '.join(py_cmd)}")

    use_tls = '--tls' in sys.argv
    protocol = "https" if use_tls else "http"

    # 1. Tu dong don dep cac port bi ket
    all_ports = [node['port'] for node in net_cfg['nodes']] + [8080]
    print("[*] Kiem tra va giai phong port 5000-5005, 8080...")
    cleanup_ports(all_ports)
    time.sleep(0.5)

    log_dir = os.path.join(base_dir, 'logs')
    os.makedirs(log_dir, exist_ok=True)

    processes = []
    log_files = []

    try:
        print(f"\n[*] 1. Dang khoi dong 6 Node P2P Mesh (Giao thuc: {protocol.upper()})...")
        for node in net_cfg['nodes']:
            cmd = py_cmd + ['blockchain/blockchain.py', '-p', str(node['port'])]
            if use_tls:
                cmd.append('--tls')
            if node['peers']:
                cmd.extend(['--peers', ','.join(node['peers'])])

            lf = open(os.path.join(log_dir, f"node_{node['port']}.log"), "w", encoding="utf-8")
            log_files.append(lf)
            p = subprocess.Popen(cmd, cwd=base_dir, stdout=lf, stderr=subprocess.STDOUT)
            processes.append(p)

            time.sleep(0.2)
            if p.poll() is not None:
                print(f"    [X] Node {node['id']} (Port {node['port']}) bi crash! Xem logs/node_{node['port']}.log")
            else:
                print(f"    [OK] Node {node['id']} dang chay tai: {protocol}://127.0.0.1:{node['port']} ({'MINER ⛏' if node['is_miner'] else 'RELAY'})")

        print("\n[*] 2. Dang khoi dong Blockchain Client...")
        client_lf = open(os.path.join(log_dir, "client_8080.log"), "w", encoding="utf-8")
        log_files.append(client_lf)
        p_client = subprocess.Popen(py_cmd + ['blockchain_client/blockchain_client.py', '-p', '8080'],
                                    cwd=base_dir, stdout=client_lf, stderr=subprocess.STDOUT)
        processes.append(p_client)
        time.sleep(0.2)
        print("    [OK] Client (Vi nguoi dung) tai: http://127.0.0.1:8080")

        print("\n" + "=" * 75)
        print("  DANH SACH DUONG DAN TRINH DUYET SAN SANG DE BAN MO VA TUONG TAC:")
        print("=" * 75)
        print(f"  * Tab 1 (Vi Client):   http://localhost:8080/make/transaction")
        print(f"  * Tab 2 (Node 1):      {protocol}://localhost:5000  (Ingress / Relay)")
        print(f"  * Tab 3 (Node 2):      {protocol}://localhost:5001  (Miner ⛏ - Co nut bam Mine)")
        print(f"  * Tab 4 (Node 3):      {protocol}://localhost:5002  (Relay)")
        print(f"  * Tab 5 (Node 4):      {protocol}://localhost:5003  (Relay)")
        print(f"  * Tab 6 (Node 5):      {protocol}://localhost:5004  (Relay)")
        print(f"  * Tab 7 (Node 6):      {protocol}://localhost:5005  (Relay)")
        print(f"  * VISUALIZER LIVE:     {protocol}://localhost:5000/visualizer (Hoac bat ky Node nao)")
        print("-" * 75)
        print("  Luu y quan trong khi dung TLS/HTTPS:")
        if use_tls:
            print("  - Do dung chung chi tu ky (Self-signed Certificate):")
            print("    Khi mo trinh duyet lan dau vao https://localhost:5000 hoac https://localhost:5001,")
            print("    trinh duyet se bao 'Ket noi khong an toan' / 'Your connection is not private'.")
            print("    Hay bam 'Advanced' (Nang cao) -> 'Proceed to localhost (unsafe)' / 'Tiep tuc truy cap'")
            print("    de trinh duyet tin tuong chung chi va cho phep AJAX ket noi.")
        print("  - Cac tab Node co che do 'Live Sync (2s)' tu dong cap nhat khong can F5.")
        if use_tls:
            print("  - Giao thuc PQC-TLS: Ho tro trao doi khoa ML-KEM-768 (NIST FIPS 203) truc tiep giua Client & Node.")
        print("  - Hop den 'Security Audit Trail' se in chi tiet qua trinh [PQC-TLS] KEM Handshake, verify MLDSA-44 & Merge Block.")
        print("=" * 75)
        print("\n>>> MANG DANG HOAT DONG. Nhan 'Ctrl+C' de dung toan bo mang <<<\n")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[*] Nhan tin hieu dung tu ban phim...")
    finally:
        print("[*] Dang tat an toan toan bo 7 tien trinh...")
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
        for lf in log_files:
            try:
                lf.close()
            except Exception:
                pass
        print("[*] Da tat toan bo mang Blockchain. Tam biet!")


if __name__ == '__main__':
    main()
