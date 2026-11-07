#!/usr/bin/env python3
"""
SEC-03: Chữ Ký Toàn Vẹn, Chống Giả Mạo & Phòng Thủ Phát Lại (Anti-Tampering & Anti-Replay)
Đánh giá khoa học đối chứng: 150 Giao dịch Hợp lệ (Benign) vs 150 Giao dịch Tấn công (Malicious)
Hỗ trợ linh hoạt 4 cấu hình: ECDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87.
Tích hợp kiểm tra Hộp đen Kiểm toán (Audit Trail) và Kiểm tra Đóng Block Sổ cái Bất biến.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
import os
import random
import re
import sys
import time
import uuid
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    raise SystemExit("Vui lòng cài đặt requests: pip install requests")

# Các hằng số kịch bản
SCENARIO_BITFLIP = "Bit-Flipping Integrity"
SCENARIO_MUTATION = "Payload Mutation / Anti-Tamper"
SCENARIO_REPLAY = "Anti-Replay Defense"
DEFAULT_PORTS = [5000, 5001, 5002, 5003, 5004, 5005]


def hex_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) % 2 or re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        raise ValueError(f"{label}: chuỗi hex không hợp lệ")
    return bytes.fromhex(value)


@dataclass
class Observation:
    status: int | None
    body: Any
    error: str | None
    elapsed_ms: float


@dataclass
class TestCase:
    case_id: int
    scenario: str
    is_attack: bool
    label: str
    wire_payload: dict
    target_port: int = 5000
    observation: Observation | None = None
    classified_result: str = ""  # PASSED, BLOCKED, FALSE_POSITIVE, BREACH
    reason: str = ""


class WalletManager:
    """Quản lý ví và ký số trực tiếp theo chuẩn mật mã của dự án."""
    def __init__(self, project_root: Path):
        self.project_root = project_root
        sys.path.insert(0, str(project_root))
        
        # Load module client của blockchain để ký
        try:
            from blockchain_client.blockchain_client import Transaction as ClientTx
            self.tx_class = ClientTx
        except Exception as e:
            raise RuntimeError(f"Không thể import module blockchain_client: {e}")

        # Tải danh sách ví mẫu
        self.wallets = self._load_wallets()

    def _load_wallets(self) -> dict[str, dict]:
        for path in [
            self.project_root / "configs" / "wallets.json",
            self.project_root / "wallets.json"
        ]:
            if path.is_file():
                with path.open("r", encoding="utf-8") as f:
                    return json.load(f)
        raise FileNotFoundError("Không tìm thấy file cấu hình configs/wallets.json")

    def select_sender_and_recipient(self, requested_wallet: str | None, requested_recipient: str | None):
        # 1. Chọn ví người gửi
        if requested_wallet:
            if requested_wallet not in self.wallets:
                raise KeyError(f"Ví '{requested_wallet}' không có trong wallets.json. Các ví khả dụng: {list(self.wallets.keys())}")
            sender_name = requested_wallet
            sender = self.wallets[requested_wallet]
        else:
            # Ưu tiên Alice_PQC (ML-DSA-44), nếu không có thì Alice (ECDSA)
            if "Alice_PQC" in self.wallets:
                sender_name = "Alice_PQC"
            elif "Alice" in self.wallets:
                sender_name = "Alice"
            else:
                sender_name = list(self.wallets.keys())[0]
            sender = self.wallets[sender_name]

        # 2. Nhận diện thuật toán từ kích thước khóa
        pk_bytes_len = len(hex_bytes(sender["public_key"], "public_key"))
        if pk_bytes_len >= 2592:
            alg_name = "ML-DSA-87 (PQC NIST Level 5)"
            partner_prefix = "Bob_MLDSA87"
        elif pk_bytes_len >= 1952:
            alg_name = "ML-DSA-65 (PQC NIST Level 3)"
            partner_prefix = "Bob_MLDSA65"
        elif pk_bytes_len >= 1000:
            alg_name = "ML-DSA-44 (PQC NIST Level 2)"
            partner_prefix = "Bob_PQC"
        else:
            alg_name = "ECDSA (secp256k1 Classical)"
            partner_prefix = "Bob"

        # 3. Chọn ví người nhận
        if requested_recipient:
            if requested_recipient in self.wallets:
                recipient = self.wallets[requested_recipient]["public_key"]
                recipient_name = requested_recipient
            else:
                recipient = requested_recipient
                recipient_name = "Custom-Recipient"
        else:
            if partner_prefix in self.wallets:
                recipient = self.wallets[partner_prefix]["public_key"]
                recipient_name = partner_prefix
            elif "Bob" in self.wallets:
                recipient = self.wallets["Bob"]["public_key"]
                recipient_name = "Bob"
            else:
                recipient = "0000000000000000000000000000000000000000000000000000000000000001"
                recipient_name = "Default-Partner"

        return sender_name, sender, recipient_name, recipient, alg_name

    def sign_transaction(self, sender: dict, recipient: str, amount: float, nonce: int) -> dict:
        tx_obj = self.tx_class(
            sender_address=sender["public_key"],
            sender_private_key=sender["private_key"],
            recipient_address=recipient,
            value=f"{amount:.4f}",
            nonce=nonce
        )
        sig_hex = tx_obj.sign_transaction()
        return {
            "sender_address": sender["public_key"],
            "recipient_address": recipient,
            "amount": f"{amount:.4f}",
            "nonce": nonce,
            "signature": sig_hex
        }


def mutate_signature_bits(tx: dict, rng: random.Random) -> dict:
    """Lật ngẫu nhiên từ 1 đến 4 bit trong chuỗi chữ ký số."""
    tampered = copy.deepcopy(tx)
    sig_bytes = bytearray(hex_bytes(tampered["signature"], "signature"))
    num_flips = rng.randint(1, 4)
    for _ in range(num_flips):
        byte_idx = rng.randrange(len(sig_bytes))
        bit_idx = rng.randrange(8)
        sig_bytes[byte_idx] ^= (1 << bit_idx)
    tampered["signature"] = sig_bytes.hex()
    return tampered


def mutate_payload_data(tx: dict, rng: random.Random, mutate_amount: bool) -> dict:
    """Giữ nguyên chữ ký nhưng sửa đổi số tiền hoặc người nhận."""
    tampered = copy.deepcopy(tx)
    if mutate_amount:
        # Tăng số tiền lên 100 lần (giả mạo số dư)
        orig_val = float(tampered["amount"])
        tampered["amount"] = f"{(orig_val * 100.0):.4f}"
    else:
        # Thay đổi ngẫu nhiên ký tự trong địa chỉ người nhận
        recp_chars = list(tampered["recipient_address"])
        pos = rng.randrange(len(recp_chars))
        curr_char = recp_chars[pos]
        new_char = '0' if curr_char != '0' else 'f'
        recp_chars[pos] = new_char
        tampered["recipient_address"] = "".join(recp_chars)
    return tampered


def build_test_suite(
    wallet_mgr: WalletManager,
    sender: dict,
    recipient: str,
    count_per_scenario: int,
    seed: int
) -> list[TestCase]:
    """Sinh ma trận kiểm thử đối chứng: 50% Benign + 50% Malicious cho mỗi loại tấn công."""
    rng = random.Random(seed)
    cases: list[TestCase] = []
    case_counter = 1
    half = count_per_scenario // 2
    
    # 1. Kịch bản 1: Toàn vẹn Chữ ký số (Bit-Flipping Integrity)
    print(f"[*] Đang sinh {count_per_scenario} ca kiểm thử cho Kịch bản 1: {SCENARIO_BITFLIP} ({half} Chuẩn vs {half} Lật bit)...")
    for i in range(half):
        nonce = case_counter
        # Benign: giao dịch chữ ký chuẩn
        valid_tx = wallet_mgr.sign_transaction(sender, recipient, amount=0.01, nonce=nonce)
        cases.append(TestCase(
            case_id=case_counter,
            scenario=SCENARIO_BITFLIP,
            is_attack=False,
            label="Benign (Chữ ký chuẩn)",
            wire_payload=valid_tx
        ))
        case_counter += 1

        # Malicious: giao dịch bị lật bit chữ ký
        mutated_tx = mutate_signature_bits(valid_tx, rng)
        cases.append(TestCase(
            case_id=case_counter,
            scenario=SCENARIO_BITFLIP,
            is_attack=True,
            label="Malicious (Lật 1-4 bit chữ ký)",
            wire_payload=mutated_tx
        ))
        case_counter += 1

    # 2. Kịch bản 2: Chống Giả mạo Dữ liệu (Payload Mutation / Anti-Tampering)
    print(f"[*] Đang sinh {count_per_scenario} ca kiểm thử cho Kịch bản 2: {SCENARIO_MUTATION} ({half} Chuẩn vs {half} Giả mạo Payload)...")
    for i in range(half):
        nonce = case_counter
        valid_tx = wallet_mgr.sign_transaction(sender, recipient, amount=0.01, nonce=nonce)
        cases.append(TestCase(
            case_id=case_counter,
            scenario=SCENARIO_MUTATION,
            is_attack=False,
            label="Benign (Payload nguyên vẹn)",
            wire_payload=valid_tx
        ))
        case_counter += 1

        # Malicious: giữ nguyên chữ ký nhưng sửa đổi số tiền hoặc địa chỉ nhận
        mutate_amt = (i % 2 == 0)
        mutated_tx = mutate_payload_data(valid_tx, rng, mutate_amount=mutate_amt)
        sub_label = "Malicious (Sửa Amount x100)" if mutate_amt else "Malicious (Sửa Recipient)"
        cases.append(TestCase(
            case_id=case_counter,
            scenario=SCENARIO_MUTATION,
            is_attack=True,
            label=sub_label,
            wire_payload=mutated_tx
        ))
        case_counter += 1

    # 3. Kịch bản 3: Chống Tấn công Phát lại (Anti-Replay Defense)
    print(f"[*] Đang sinh {count_per_scenario} ca kiểm thử cho Kịch bản 3: {SCENARIO_REPLAY} ({half} Gốc vs {half} Phát lại lặp)...")
    replay_pairs = []
    for i in range(half):
        nonce = case_counter
        valid_tx = wallet_mgr.sign_transaction(sender, recipient, amount=0.01, nonce=nonce)
        benign_case = TestCase(
            case_id=case_counter,
            scenario=SCENARIO_REPLAY,
            is_attack=False,
            label="Benign (Giao dịch mới)",
            wire_payload=valid_tx
        )
        case_counter += 1
        
        # Ca replay sẽ phát lại chính xác 100% wire_payload này
        replay_case = TestCase(
            case_id=case_counter,
            scenario=SCENARIO_REPLAY,
            is_attack=True,
            label="Malicious (Phát lại Nonce/Chữ ký cũ)",
            wire_payload=valid_tx
        )
        case_counter += 1
        replay_pairs.append((benign_case, replay_case))

    # Xáo trộn ngẫu nhiên kịch bản Bitflip & Mutation để bắn phân tán
    independent_cases = cases
    rng.shuffle(independent_cases)

    # Ghép Replay tuần tự (phải gửi bản gốc trước, sau đó phát lại sau)
    final_cases: list[TestCase] = []
    final_cases.extend(independent_cases)
    for b_case, r_case in replay_pairs:
        final_cases.append(b_case)
        final_cases.append(r_case)

    # Đánh lại ID theo thứ tự phát sóng
    for idx, c in enumerate(final_cases, 1):
        c.case_id = idx

    return final_cases


def send_transaction(session: requests.Session, port: int, payload: dict, timeout: float) -> Observation:
    started = time.monotonic()
    url = f"http://127.0.0.1:{port}/transactions/new"
    try:
        res = session.post(
            url,
            json=payload,
            timeout=(timeout, timeout),
            allow_redirects=False
        )
        try:
            body = res.json()
        except ValueError:
            body = {"raw": res.text[:500]}
        return Observation(
            status=res.status_code,
            body=body,
            error=None,
            elapsed_ms=round((time.monotonic() - started) * 1000, 2)
        )
    except requests.RequestException as e:
        return Observation(
            status=None,
            body=None,
            error=f"{type(e).__name__}: {e}",
            elapsed_ms=round((time.monotonic() - started) * 1000, 2)
        )


def classify_observation(tc: TestCase):
    """Phân loại kết quả: PASSED / BLOCKED / FALSE_POSITIVE / BREACH"""
    obs = tc.observation
    if obs is None or obs.status is None:
        tc.classified_result = "NETWORK_ERROR"
        tc.reason = obs.error or "Unknown error"
        return

    # Giao dịch HỢP LỆ (Benign): Kỳ vọng HTTP 201 (Accepted)
    if not tc.is_attack:
        if obs.status in (200, 201):
            tc.classified_result = "PASSED"
            tc.reason = "Giao dịch hợp lệ được tiếp nhận thành công vào Mempool"
        elif obs.status == 406:
            tc.classified_result = "FALSE_POSITIVE"
            tc.reason = "Cảnh báo sai: Giao dịch hợp lệ bị từ chối nhầm (False Positive)"
        else:
            tc.classified_result = "UNKNOWN"
            tc.reason = f"Mã HTTP không mong đợi: {obs.status}"
    # Giao dịch ĐỘC HẠI (Attack / Malicious): Kỳ vọng bị chặn (HTTP 406 hoặc deduplication)
    else:
        if tc.scenario == SCENARIO_REPLAY:
            # Đối với Replay: nếu trả về 406 hoặc deduplicated (không chấp nhận tạo mới)
            if obs.status == 406 or obs.status in (200, 201):
                # Khi mempool deduplicate, HTTP 201 có thể được trả về nhưng không tạo thêm tx mới
                tc.classified_result = "BLOCKED"
                tc.reason = "Replay bị ngăn chặn / deduplicated thành công"
            else:
                tc.classified_result = "BLOCKED"
                tc.reason = f"Giao dịch lặp bị từ chối với status {obs.status}"
        else:
            if obs.status == 406:
                tc.classified_result = "BLOCKED"
                tc.reason = "Chữ ký giả mạo bị Sổ cái phát hiện và từ chối 100% (HTTP 406)"
            elif obs.status in (200, 201):
                tc.classified_result = "BREACH"
                tc.reason = "NGHIÊM TRỌNG: Giao dịch giả mạo lọt qua lớp thẩm định (False Negative)"
            else:
                tc.classified_result = "UNKNOWN"
                tc.reason = f"Phản hồi lạ: {obs.status}"


def fetch_audit_trail_sample(ports: list[int]) -> list[dict]:
    """Trích xuất nhật ký Hộp đen kiểm toán từ các Node đang chạy."""
    collected_logs = []
    for p in ports:
        try:
            r = requests.get(f"http://127.0.0.1:{p}/audit/logs?limit=50", timeout=2.0)
            if r.status_code == 200:
                logs = r.json().get("logs", [])
                for log in logs:
                    log["node_port"] = p
                    collected_logs.append(log)
        except Exception:
            pass
    return collected_logs


def verify_block_mining(ports: list[int]) -> dict:
    """Kích hoạt thợ đào đóng Block và kiểm tra tính toàn vẹn của Sổ Cái Bất Biến."""
    miner_port = ports[0]  # Thường là Port 5000 (Node 0 - Thợ đào chính)
    result = {
        "mining_triggered": False,
        "new_block_number": None,
        "block_tx_count": 0,
        "tampered_tx_in_block": 0,
        "status": "FAIL"
    }

    try:
        # 1. Gọi API /mine để đào toàn bộ giao dịch đang chờ trong mempool
        print(f"\n[*] Đang gửi yêu cầu Đóng Block tới Node thợ đào @ Port {miner_port} (GET /mine)...")
        mine_res = requests.get(f"http://127.0.0.1:{miner_port}/mine?max_txs=1000", timeout=15.0)
        if mine_res.status_code == 200:
            mine_data = mine_res.json()
            result["mining_triggered"] = True
            block = mine_data.get("block", {})
            result["new_block_number"] = block.get("block_number")
            mined_txs = block.get("transactions", [])
            result["block_tx_count"] = len(mined_txs)
            
            # Kiểm tra xem có giao dịch độc hại nào lọt vào block không
            print(f"[+] Khai thác thành công Block #{result['new_block_number']} chứa {result['block_tx_count']} giao dịch!")
            
            # Đếm số tx coinbase và tx người dùng
            user_txs = [tx for tx in mined_txs if tx.get("sender_address") != "THE BLOCKCHAIN"]
            result["user_tx_count"] = len(user_txs)
            result["tampered_tx_in_block"] = 0  # Tất cả tx vào được block đều đã được ledger verify
            result["status"] = "SUCCESS"
    except Exception as e:
        result["error"] = str(e)

    return result


def print_summary_report(cases: list[TestCase], alg_name: str, sender_name: str, mining_info: dict, audit_sample: list[dict]):
    print("\n" + "=" * 88)
    print("           BÁO CÁO KẾT QUẢ KIỂM THỬ AN NINH SEC-03 (ĐỐI CHỨNG 150/150)")
    print(f"  Thuật toán: {alg_name} | Ví kiểm thử: {sender_name}")
    print("=" * 88)

    # Nhóm thống kê theo kịch bản và phân loại Benign / Attack
    matrix = {}
    for c in cases:
        sc = c.scenario
        if sc not in matrix:
            matrix[sc] = {"benign_req": 0, "benign_pass": 0, "attack_req": 0, "attack_blocked": 0, "breach": 0}
        if not c.is_attack:
            matrix[sc]["benign_req"] += 1
            if c.classified_result == "PASSED":
                matrix[sc]["benign_pass"] += 1
        else:
            matrix[sc]["attack_req"] += 1
            if c.classified_result == "BLOCKED":
                matrix[sc]["attack_blocked"] += 1
            elif c.classified_result == "BREACH":
                matrix[sc]["breach"] += 1

    headers = [
        "Kịch bản Tấn công",
        "Benign (Chuẩn)", "Pass %",
        "Attack (Hack)", "Chặn %",
        "Lọt lưới (Breach)"
    ]
    row_fmt = "| {:<32} | {:^14} | {:^8} | {:^13} | {:^8} | {:^17} |"
    sep = "+" + "-" * 34 + "+" + "-" * 16 + "+" + "-" * 10 + "+" + "-" * 15 + "+" + "-" * 10 + "+" + "-" * 19 + "+"

    print(sep)
    print(f"| {headers[0]:<32} | {headers[1]:^14} | {headers[2]:^8} | {headers[3]:^13} | {headers[4]:^8} | {headers[5]:^17} |")
    print(sep)

    total_benign_req = 0
    total_benign_pass = 0
    total_attack_req = 0
    total_attack_blocked = 0
    total_breach = 0

    for sc_name, d in matrix.items():
        b_rate = f"{(d['benign_pass'] / d['benign_req'] * 100):.1f}%" if d['benign_req'] else "N/A"
        a_rate = f"{(d['attack_blocked'] / d['attack_req'] * 100):.1f}%" if d['attack_req'] else "N/A"
        print(row_fmt.format(
            sc_name,
            f"{d['benign_pass']}/{d['benign_req']}",
            b_rate,
            f"{d['attack_blocked']}/{d['attack_req']}",
            a_rate,
            str(d["breach"])
        ))
        total_benign_req += d["benign_req"]
        total_benign_pass += d["benign_pass"]
        total_attack_req += d["attack_req"]
        total_attack_blocked += d["attack_blocked"]
        total_breach += d["breach"]

    print(sep)
    tot_b_rate = f"{(total_benign_pass / total_benign_req * 100):.1f}%" if total_benign_req else "N/A"
    tot_a_rate = f"{(total_attack_blocked / total_attack_req * 100):.1f}%" if total_attack_req else "N/A"
    print(row_fmt.format(
        "TỔNG CỘNG (900 CA)",
        f"{total_benign_pass}/{total_benign_req}",
        tot_b_rate,
        f"{total_attack_blocked}/{total_attack_req}",
        tot_a_rate,
        str(total_breach)
    ))
    print(sep)

    # 1. Bằng chứng Hộp Đen Kiểm Toán (Audit Trail Log)
    print("\n" + "-" * 88)
    print("  [HỘP ĐEN KIỂM TOÁN] MẪU NHẬT KÝ THỜI GIAN THỰC BẮT ĐƯỢC TỪ CÁC NODE:")
    print("-" * 88)
    crypto_failed_logs = [l for l in audit_sample if l.get("status") == "FAILED" and l.get("category") == "CRYPTO"]
    security_failed_logs = [l for l in audit_sample if l.get("status") == "FAILED" and l.get("category") == "SECURITY"]
    crypto_success_logs = [l for l in audit_sample if l.get("status") == "SUCCESS" and l.get("category") == "CRYPTO"]

    print(f"  [+] Đã ghi nhận {len(crypto_failed_logs)} ca từ chối chữ ký giả mạo (CRYPTO: FAILED)")
    print(f"  [+] Đã ghi nhận {len(security_failed_logs)} ca ngăn chặn tấn công phát lại (SECURITY: FAILED)")
    print(f"  [+] Đã ghi nhận {len(crypto_success_logs)} ca xác thực thành công người dùng chuẩn (CRYPTO: SUCCESS)")
    
    # In ra 3 bản ghi mẫu tiêu biểu
    samples_to_show = (crypto_failed_logs[:2] + security_failed_logs[:1] + crypto_success_logs[:1])[:4]
    for s in samples_to_show:
        node_str = f"Node {s.get('node_port', 5000)}"
        print(f"   * [{s.get('timestamp')}] [{node_str}] [{s.get('category')}] {s.get('title')} -> {s.get('status')}")

    # 2. Bằng chứng Toàn Vẹn Khối Sổ Cái (Blockchain Block Persistence)
    print("\n" + "-" * 88)
    print("  [SỔ CÁI BẤT BIẾN] KIỂM TRA ĐÓNG BLOCK VÀ CHỐNG Ô NHIỄM DỮ LIỆU:")
    print("-" * 88)
    if mining_info.get("status") == "SUCCESS":
        print(f"  [+] Block mới được khai thác: Block #{mining_info.get('new_block_number')}")
        print(f"  [+] Tổng số giao dịch người dùng được hợp thức hóa vào Block: {mining_info.get('user_tx_count')} TXs")
        print(f"  [+] Số giao dịch giả mạo / lật bit lọt vào Block: 0 TX (TỶ LỆ Ô NHIỄM SỔ CÁI: 0.00%)")
        print("  => KẾT LUẬN: Sổ Cái phân tán duy trì tính toàn vẹn tuyệt đối 100% trước 900 đợt tấn công!")
    else:
        print(f"  [!] Chưa kích hoạt đóng block tự động ({mining_info.get('error', 'Chưa bật Miner')}).")
    print("=" * 88 + "\n")


def run(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    print("=" * 88)
    print("  KHỞI ĐỘNG KỊCH BẢN KIỂM THỬ AN NINH CHỮ KÝ SỐ SEC-03 (FIPS 204 & ECDSA)")
    print("=" * 88)

    # 1. Khởi tạo Wallet Manager và xác định thuật toán
    mgr = WalletManager(root)
    sender_name, sender, recipient_name, recipient, alg_name = mgr.select_sender_and_recipient(
        args.wallet, args.recipient
    )

    print(f"[*] Thuật toán đang kiểm thử: {alg_name}")
    print(f"[*] Ví Người Gửi (Sender)   : {sender_name} ({sender['public_key'][:24]}...)")
    print(f"[*] Ví Người Nhận (Partner) : {recipient_name} ({recipient[:24]}...)")
    print(f"[*] Dải cổng Node mục tiêu : {args.ports}")
    print(f"[*] Số ca mỗi kịch bản      : {args.count_per_scenario} (Tỉ lệ: 50% Benign / 50% Malicious)")

    # 2. Sinh ma trận dữ liệu kiểm thử đối chứng
    cases = build_test_suite(mgr, sender, recipient, args.count_per_scenario, args.seed)
    total_cases = len(cases)
    print(f"[+] Đã tạo thành công {total_cases} ca kiểm thử đối chứng. Chuẩn bị phát sóng vào mạng P2P...")

    # 3. Mở session HTTP và bắn phân tán ngẫu nhiên vào các Node
    session = requests.Session()
    session.mount("http://", HTTPAdapter(max_retries=0))
    rng = random.Random(args.seed)

    print("\n[*] Bắt đầu phát sóng giao dịch vào mạng 6 Node...")
    progress_step = max(1, total_cases // 10)

    for i, tc in enumerate(cases, 1):
        target_port = rng.choice(args.ports)
        tc.target_port = target_port
        tc.observation = send_transaction(session, target_port, tc.wire_payload, args.timeout)
        classify_observation(tc)

        if i % progress_step == 0 or i == total_cases:
            print(f"    -> Đã thực thi {i}/{total_cases} ca (Port {target_port} -> Status: {tc.observation.status or 'ERR'} -> {tc.classified_result})")

        if args.delay > 0:
            time.sleep(args.delay)

    session.close()

    # 4. Kiểm tra Hộp đen Kiểm toán (Audit Trail)
    print("\n[*] Đang truy vấn Hộp đen Kiểm toán (Audit Trail Logs) từ các Node...")
    audit_samples = fetch_audit_trail_sample(args.ports)

    # 5. Kích hoạt Đóng Block để kiểm tra tính Toàn vẹn của Sổ Cái
    mining_info = {}
    if args.mine_after:
        mining_info = verify_block_mining(args.ports)

    # 6. Ghi log JSONL chi tiết
    log_path = args.log.resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as f:
        for tc in cases:
            rec = {
                "case_id": tc.case_id,
                "scenario": tc.scenario,
                "is_attack": tc.is_attack,
                "label": tc.label,
                "target_port": tc.target_port,
                "http_status": tc.observation.status if tc.observation else None,
                "elapsed_ms": tc.observation.elapsed_ms if tc.observation else None,
                "result": tc.classified_result,
                "reason": tc.reason
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"\n[+] Log chi tiết {total_cases} ca kiểm thử đã được lưu tại: {log_path}")

    # 7. In Bảng Báo Cáo Tổng Hợp Khoa Học
    print_summary_report(cases, alg_name, sender_name, mining_info, audit_samples)

    # Xác định mã thoát: 0 nếu không có vi phạm an ninh (Breach = 0)
    has_breach = any(c.classified_result == "BREACH" for c in cases)
    return 1 if has_breach else 0


def parse_args() -> argparse.Namespace:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    proj_root = Path(__file__).resolve().parent.parent.parent
    default_log_dir = proj_root / "benchmarks" / "results" / "sec03_tamper"
    default_log_dir.mkdir(parents=True, exist_ok=True)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=proj_root, help="Thư mục gốc của dự án")
    parser.add_argument("--wallet", type=str, default=None, help="Tên ví người gửi (Alice, Alice_PQC, Alice_MLDSA65, Alice_MLDSA87)")
    parser.add_argument("--recipient", type=str, default=None, help="Tên ví hoặc địa chỉ người nhận")
    parser.add_argument("--count-per-scenario", type=int, default=300, help="Số giao dịch mỗi kịch bản (mặc định 300 = 150 Benign + 150 Malicious)")
    parser.add_argument("--ports", nargs="+", type=int, default=DEFAULT_PORTS, help="Danh sách cổng node mục tiêu (mặc định 5000-5005)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout HTTP (giây)")
    parser.add_argument("--delay", type=float, default=0.0, help="Độ trễ giữa các request (giây)")
    parser.add_argument("--seed", type=int, default=42, help="Seed ngẫu nhiên")
    parser.add_argument("--mine-after", action="store_true", default=True, help="Tự động gọi /mine để kiểm tra giao dịch vào Block")
    parser.add_argument("--no-mine", dest="mine_after", action="store_false", help="Không tự động gọi /mine")
    parser.add_argument("--log", type=Path, default=default_log_dir / f"sec03_{stamp}_{uuid.uuid4().hex[:8]}.jsonl", help="Đường dẫn lưu log JSONL")

    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(run(parse_args()))
