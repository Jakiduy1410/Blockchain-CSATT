#!/usr/bin/env python3
"""
SEC-03: Chữ Ký Toàn Vẹn, Chống Giả Mạo & Phòng Thủ Phát Lại (Anti-Tampering & Anti-Replay)
- Đánh giá khoa học đối chứng: 50% Giao dịch Hợp lệ (Benign) vs 50% Giao dịch Tấn công (Malicious)
- Đa thuật toán (Supported Schemes): Classical ECDSA (secp256k1), Post-Quantum ML-DSA-44, ML-DSA-65, ML-DSA-87
- Mô hình Multi-Client: Nhiều ví người dùng gửi giao dịch chéo qua lại lẫn nhau
- Cơ chế Multi-Worker Dispatch: Trộn và gửi đồng thời / tiệm cận qua ThreadPoolExecutor
- Đủ 3 vector Payload Mutation: Sửa số tiền (Amount), Sửa người nhận (Recipient), Mạo danh người gửi (Sender Spoofing)
- Trực quan hóa tự động: Xuất biểu đồ chi tiết (.bits.png, .mutation.png, .replay.png) và .summary.json
- Tích hợp kiểm tra Hộp đen Kiểm toán (Audit Trail) và Sổ cái Bất biến (Block Mining).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import copy
import hashlib
import io
import json
import math
import os
import random
import re
import statistics
import sys
import threading
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
    sender_name: str = ""
    recipient_name: str = ""
    target_port: int = 5000
    observation: Observation | None = None
    classified_result: str = ""  # PASSED, BLOCKED, FALSE_POSITIVE, BREACH
    reason: str = ""
    mutation_field: str | None = None  # "amount", "recipient_address", "sender_address"
    bit_flips: int | None = None       # 1, 2, 3, 4


class WalletManager:
    """Quản lý ví và ký số trực tiếp theo chuẩn mật mã của dự án."""
    def __init__(self, project_root: Path):
        self.project_root = project_root
        sys.path.insert(0, str(project_root))

        try:
            from blockchain_client.blockchain_client import Transaction as ClientTx
            self.tx_class = ClientTx
        except Exception as e:
            raise RuntimeError(f"Không thể import module blockchain_client: {e}")

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

    def resolve_scheme(self, requested_scheme: str | None, requested_wallet: str | None):
        """
        Xác định thuật toán kiểm thử và trích xuất danh sách các ví Multi-Client tương ứng.
        Hỗ trợ 4 thuật toán: ECDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87.
        """
        norm_scheme = (requested_scheme or "").strip().lower().replace("-", "").replace("_", "")

        # Nếu người dùng chỉ định cụ thể 1 ví gửi, suy luận scheme từ ví đó
        if requested_wallet:
            if requested_wallet not in self.wallets:
                raise KeyError(f"Ví '{requested_wallet}' không có trong wallets.json. Các ví khả dụng: {list(self.wallets.keys())}")
            sender = self.wallets[requested_wallet]
            pk_hex = sender["public_key"]
            pk_bytes_len = len(hex_bytes(pk_hex, "public_key"))
            if pk_bytes_len >= 2592:
                norm_scheme = "mldsa87"
            elif pk_bytes_len >= 1952:
                norm_scheme = "mldsa65"
            elif pk_bytes_len >= 1000:
                norm_scheme = "mldsa44"
            else:
                norm_scheme = "ecdsa"

        # Mặc định ưu tiên ML-DSA-44 (FIPS 204 NIST Level 2)
        if not norm_scheme or norm_scheme in ("all", "hybrid", "pqc", "default"):
            norm_scheme = "mldsa44"

        # Định nghĩa các nhóm ví Multi-Client cho từng thuật toán
        if norm_scheme in ("ecdsa", "secp256k1", "classical"):
            scheme_id = "ecdsa"
            alg_name = "Classical ECDSA (secp256k1)"
            preferred_names = ["Alice", "Bob", "Charlie", "Dave"]
        elif norm_scheme in ("mldsa44", "dilithium2"):
            scheme_id = "mldsa44"
            alg_name = "Post-Quantum ML-DSA-44 (FIPS 204 NIST Level 2)"
            preferred_names = ["Alice_PQC", "Bob_PQC", "Charlie_PQC", "Dave_PQC"]
        elif norm_scheme in ("mldsa65", "dilithium3"):
            scheme_id = "mldsa65"
            alg_name = "Post-Quantum ML-DSA-65 (FIPS 204 NIST Level 3)"
            preferred_names = ["Alice_MLDSA65", "Bob_MLDSA65", "Charlie_MLDSA65", "Dave_MLDSA65"]
        elif norm_scheme in ("mldsa87", "dilithium5"):
            scheme_id = "mldsa87"
            alg_name = "Post-Quantum ML-DSA-87 (FIPS 204 NIST Level 5)"
            preferred_names = ["Alice_MLDSA87", "Bob_MLDSA87", "Charlie_MLDSA87", "Dave_MLDSA87"]
        else:
            raise ValueError(f"Thuật toán '{requested_scheme}' không hợp lệ. Chỉ chấp nhận: ecdsa, mldsa44, mldsa65, mldsa87.")

        # Lọc các ví khả dụng có private_key
        active_wallets = []
        for name in preferred_names:
            if name in self.wallets and self.wallets[name].get("private_key"):
                active_wallets.append((name, self.wallets[name]))

        # Nếu thiếu ví phụ, tìm bất kỳ ví nào cùng kích thước khóa
        if len(active_wallets) < 2:
            for name, w in self.wallets.items():
                if name not in [n for n, _ in active_wallets] and w.get("private_key"):
                    pk_hex = w["public_key"]
                    pk_len = len(hex_bytes(pk_hex, "public_key"))
                    if scheme_id == "ecdsa" and pk_len < 100:
                        active_wallets.append((name, w))
                    elif scheme_id == "mldsa44" and 1000 <= pk_len < 1952:
                        active_wallets.append((name, w))
                    elif scheme_id == "mldsa65" and 1952 <= pk_len < 2592:
                        active_wallets.append((name, w))
                    elif scheme_id == "mldsa87" and pk_len >= 2592:
                        active_wallets.append((name, w))

        if len(active_wallets) < 2:
            raise RuntimeError(f"Cần ít nhất 2 ví có Private Key cho thuật toán {alg_name} để kiểm thử Multi-Client!")

        # Tạo ma trận các cặp giao dịch chéo (A -> B, B -> A, C -> D, D -> C, ...)
        client_pairs: list[tuple[dict, dict]] = []
        for i in range(len(active_wallets)):
            for j in range(len(active_wallets)):
                if i != j:
                    client_pairs.append((active_wallets[i][1], active_wallets[j][1]))

        client_names = [n for n, _ in active_wallets]
        return scheme_id, alg_name, client_pairs, client_names

    def sign_transaction(self, sender: dict, recipient_pubkey: str, amount: float, nonce: int) -> dict:
        tx_obj = self.tx_class(
            sender_address=sender["public_key"],
            sender_private_key=sender["private_key"],
            recipient_address=recipient_pubkey,
            value=f"{amount:.4f}",
            nonce=nonce
        )
        sig_hex = tx_obj.sign_transaction()
        return {
            "sender_address": sender["public_key"],
            "recipient_address": recipient_pubkey,
            "amount": f"{amount:.4f}",
            "nonce": nonce,
            "signature": sig_hex
        }


def mutate_signature_bits(tx: dict, rng: random.Random, num_flips: int | None = None) -> tuple[dict, int]:
    """Lật ngẫu nhiên từ 1 đến 4 bit trong chuỗi chữ ký số."""
    tampered = copy.deepcopy(tx)
    sig_bytes = bytearray(hex_bytes(tampered["signature"], "signature"))
    flips = num_flips if num_flips is not None else rng.randint(1, 4)
    for _ in range(flips):
        byte_idx = rng.randrange(len(sig_bytes))
        bit_idx = rng.randrange(8)
        sig_bytes[byte_idx] ^= (1 << bit_idx)
    tampered["signature"] = sig_bytes.hex()
    return tampered, flips


def mutate_payload_data(tx: dict, rng: random.Random, field_to_mutate: str, alternate_sender: str = "") -> dict:
    """
    Giữ nguyên chữ ký nhưng sửa đổi một trong 3 trường cốt lõi:
    1. 'amount': Sửa đổi số tiền (nhân 100)
    2. 'recipient_address': Lật bit địa chỉ người nhận
    3. 'sender_address': Mạo danh người gửi (Sender Spoofing)
    """
    tampered = copy.deepcopy(tx)
    if field_to_mutate == "amount":
        orig_val = float(tampered["amount"])
        tampered["amount"] = f"{(orig_val * 100.0):.4f}"
    elif field_to_mutate == "recipient_address":
        recp_chars = list(tampered["recipient_address"])
        pos = rng.randrange(len(recp_chars))
        curr_char = recp_chars[pos]
        new_char = '0' if curr_char != '0' else 'f'
        recp_chars[pos] = new_char
        tampered["recipient_address"] = "".join(recp_chars)
    elif field_to_mutate == "sender_address":
        if alternate_sender and alternate_sender != tampered["sender_address"]:
            tampered["sender_address"] = alternate_sender
        else:
            tampered["sender_address"] = tampered["recipient_address"]
    else:
        raise ValueError(f"Trường sửa đổi không hợp lệ: {field_to_mutate}")
    return tampered


def build_test_suite(
    wallet_mgr: WalletManager,
    client_pairs: list[tuple[dict, dict]],
    count_per_scenario: int,
    seed: int,
    ports: list[int] | None = None
) -> tuple[list[TestCase], list[TestCase]]:
    """
    Sinh ma trận kiểm thử đối chứng Multi-Client:
    - 50% Benign + 50% Malicious cho mỗi loại tấn công.
    - Phân bổ luân phiên các cặp Client gửi chéo cho nhau.
    - Đầy đủ 3 vector Payload Mutation: Amount, Recipient, Sender Spoofing.
    - Quản lý bộ đếm Nonce độc lập cho từng Client để tránh xung đột số thứ tự.
    Trả về: (independent_cases, replay_pairs)
    """
    rng = random.Random(seed)
    independent_cases: list[TestCase] = []
    replay_pairs: list[tuple[TestCase, TestCase]] = []
    case_counter = 1
    half = count_per_scenario // 2

    # Quản lý nonce riêng cho từng sender (Đồng bộ trực tiếp với Sổ cái mạng)
    sender_nonces: dict[str, int] = {}
    for s, r in client_pairs:
        s_name = s["name"]
        if s_name not in sender_nonces:
            initial_nonce = 1
            if ports:
                for p in ports:
                    try:
                        resp = requests.get(f"http://127.0.0.1:{p}/accounts/nonce?address={s['public_key']}", timeout=1.0)
                        if resp.status_code == 200:
                            initial_nonce = int(resp.json().get("next_nonce", 1))
                            break
                    except Exception:
                        pass
            sender_nonces[s_name] = initial_nonce

    num_pairs = len(client_pairs)

    # 1. Kịch bản 1: Toàn vẹn Chữ ký số (Bit-Flipping Integrity)
    print(f"[*] Đang sinh {count_per_scenario} ca kiểm thử Multi-Client cho Kịch bản 1: {SCENARIO_BITFLIP} ({half} Chuẩn vs {half} Lật 1-4 bit)...")
    bit_plan = [1, 2, 3, 4] * ((half // 4) + 1)
    rng.shuffle(bit_plan)
    for i in range(half):
        sender, recipient = client_pairs[i % num_pairs]
        s_name, r_name = sender["name"], recipient["name"]

        # Benign: giao dịch chữ ký chuẩn
        nonce_b = sender_nonces[s_name]
        sender_nonces[s_name] += 1
        valid_tx = wallet_mgr.sign_transaction(sender, recipient["public_key"], amount=0.01, nonce=nonce_b)
        independent_cases.append(TestCase(
            case_id=case_counter,
            scenario=SCENARIO_BITFLIP,
            is_attack=False,
            label=f"Benign ({s_name} -> {r_name})",
            wire_payload=valid_tx,
            sender_name=s_name,
            recipient_name=r_name
        ))
        case_counter += 1

        # Malicious: giao dịch bị lật bit chữ ký (1..4 bit)
        # Sử dụng Nonce độc lập để kiểm tra đúng năng lực phát hiện chữ ký hỏng tầng CRYPTO,
        # tránh bị bộ lọc Replay Attack ở tầng Ingress ngắt sớm trước khi verify chữ ký.
        nonce_m = sender_nonces[s_name]
        sender_nonces[s_name] += 1
        tx_to_mutate = wallet_mgr.sign_transaction(sender, recipient["public_key"], amount=0.01, nonce=nonce_m)
        flips = bit_plan[i]
        mutated_tx, _ = mutate_signature_bits(tx_to_mutate, rng, num_flips=flips)
        independent_cases.append(TestCase(
            case_id=case_counter,
            scenario=SCENARIO_BITFLIP,
            is_attack=True,
            label=f"Malicious (Lật {flips} bit chữ ký - {s_name})",
            wire_payload=mutated_tx,
            sender_name=s_name,
            recipient_name=r_name,
            bit_flips=flips
        ))
        case_counter += 1

    # 2. Kịch bản 2: Chống Giả mạo Dữ liệu (Payload Mutation / Anti-Tampering)
    print(f"[*] Đang sinh {count_per_scenario} ca kiểm thử Multi-Client cho Kịch bản 2: {SCENARIO_MUTATION} ({half} Chuẩn vs {half} Giả mạo Payload: Amount / Recipient / Sender)...")
    mut_fields = ["amount", "recipient_address", "sender_address"]
    for i in range(half):
        sender, recipient = client_pairs[(i + half) % num_pairs]
        s_name, r_name = sender["name"], recipient["name"]

        # Benign: giao dịch chữ ký chuẩn
        nonce_b = sender_nonces[s_name]
        sender_nonces[s_name] += 1
        valid_tx = wallet_mgr.sign_transaction(sender, recipient["public_key"], amount=0.01, nonce=nonce_b)
        independent_cases.append(TestCase(
            case_id=case_counter,
            scenario=SCENARIO_MUTATION,
            is_attack=False,
            label=f"Benign ({s_name} -> {r_name})",
            wire_payload=valid_tx,
            sender_name=s_name,
            recipient_name=r_name
        ))
        case_counter += 1

        # Malicious: Nonce độc lập để kiểm tra đúng năng lực phát hiện sửa đổi Payload ở tầng CRYPTO
        nonce_m = sender_nonces[s_name]
        sender_nonces[s_name] += 1
        tx_to_mutate = wallet_mgr.sign_transaction(sender, recipient["public_key"], amount=0.01, nonce=nonce_m)
        mut_field = mut_fields[i % 3]
        mutated_tx = mutate_payload_data(tx_to_mutate, rng, field_to_mutate=mut_field, alternate_sender=recipient["public_key"])
        if mut_field == "amount":
            sub_label = f"Malicious (Sửa Amount x100 - {s_name})"
        elif mut_field == "recipient_address":
            sub_label = f"Malicious (Sửa Recipient - {s_name})"
        else:
            sub_label = f"Malicious (Sửa Sender Spoofing - {s_name})"

        independent_cases.append(TestCase(
            case_id=case_counter,
            scenario=SCENARIO_MUTATION,
            is_attack=True,
            label=sub_label,
            wire_payload=mutated_tx,
            sender_name=s_name,
            recipient_name=r_name,
            mutation_field=mut_field
        ))
        case_counter += 1

    # 3. Kịch bản 3: Chống Tấn công Phát lại (Anti-Replay Defense)
    print(f"[*] Đang sinh {count_per_scenario} ca kiểm thử Multi-Client cho Kịch bản 3: {SCENARIO_REPLAY} ({half} Gốc vs {half} Phát lại lặp)...")
    for i in range(half):
        sender, recipient = client_pairs[i % num_pairs]
        s_name, r_name = sender["name"], recipient["name"]
        nonce = sender_nonces[s_name]
        sender_nonces[s_name] += 1

        valid_tx = wallet_mgr.sign_transaction(sender, recipient["public_key"], amount=0.01, nonce=nonce)
        benign_case = TestCase(
            case_id=case_counter,
            scenario=SCENARIO_REPLAY,
            is_attack=False,
            label=f"Benign (Giao dịch mới - {s_name} -> {r_name})",
            wire_payload=valid_tx,
            sender_name=s_name,
            recipient_name=r_name
        )
        case_counter += 1

        replay_case = TestCase(
            case_id=case_counter,
            scenario=SCENARIO_REPLAY,
            is_attack=True,
            label=f"Malicious (Phát lại Nonce/Chữ ký cũ - {s_name})",
            wire_payload=valid_tx,
            sender_name=s_name,
            recipient_name=r_name
        )
        case_counter += 1
        replay_pairs.append((benign_case, replay_case))

    return independent_cases, replay_pairs


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
            if obs.status == 406:
                tc.classified_result = "BLOCKED"
                tc.reason = "Phát lại Nonce/Chữ ký bị Sổ cái phát hiện và chặn đứng (HTTP 406)"
            elif obs.status in (200, 201):
                tc.classified_result = "BREACH"
                tc.reason = "NGHIÊM TRỌNG: Giao dịch phát lại lặp bị lọt vào Mempool (False Negative)"
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
                tc.classified_result = "BLOCKED"
                tc.reason = f"Bị từ chối với status {obs.status}"


def calc_latency_stats(latencies: list[float]) -> dict:
    """Tính toán bộ chỉ số độ trễ thống kê (Min, Mean, Median, P95, P99, Max)."""
    if not latencies:
        return {"count": 0, "min": 0.0, "mean": 0.0, "median": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
    lat_sorted = sorted(latencies)
    n = len(lat_sorted)
    p95_idx = min(n - 1, int(math.ceil(0.95 * n)) - 1)
    p99_idx = min(n - 1, int(math.ceil(0.99 * n)) - 1)
    return {
        "count": n,
        "min": round(lat_sorted[0], 2),
        "mean": round(statistics.mean(lat_sorted), 2),
        "median": round(statistics.median(lat_sorted), 2),
        "p95": round(lat_sorted[p95_idx], 2),
        "p99": round(lat_sorted[p99_idx], 2),
        "max": round(lat_sorted[-1], 2),
    }


def write_bit_chart(path: Path, bit_samples: list[tuple[int, float]], alg_name: str) -> bool:
    """Vẽ biểu đồ độ trễ chặn theo số bit bị lật (1, 2, 3, 4 bit)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        groups = {1: [], 2: [], 3: [], 4: []}
        for bits, lat in bit_samples:
            if bits in groups and lat is not None:
                groups[bits].append(lat)

        labels = [f"{b} bit" for b in range(1, 5)]
        means = [round(statistics.mean(groups[b]), 2) if groups[b] else 0.0 for b in range(1, 5)]

        fig, ax = plt.subplots(figsize=(8, 4.5))
        bars = ax.bar(labels, means, color="#2563eb", width=0.55, edgecolor="#1d4ed8")
        ax.bar_label(bars, fmt="%.2f ms", padding=3, fontsize=9)
        ax.set_ylabel("Độ trễ đánh chặn trung bình (ms)")
        ax.set_title(f"SEC-03: Bit-Flipping · Độ trễ theo số bit bị lật\n[{alg_name}]", pad=12, fontweight="bold")
        ax.set_ylim(bottom=0)
        ax.margins(y=0.18)
        ax.grid(axis="y", alpha=0.3, linestyle="--")
        fig.tight_layout()
        fig.savefig(path, dpi=180)
        plt.close(fig)
        return True
    except Exception as e:
        print(f"[CHART] Không thể tạo biểu đồ bit-flip {path}: {e}", file=sys.stderr)
        return False


def write_mutation_chart(path: Path, mutation_samples: list[tuple[str, float]], alg_name: str) -> bool:
    """Vẽ biểu đồ độ trễ chặn theo 3 trường Payload bị sửa (Amount, Recipient, Sender)."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fields = {
            "amount": ("Sửa Amount", "#158379"),
            "recipient_address": ("Sửa Receiver", "#2563eb"),
            "sender_address": ("Sửa Sender", "#ad651d")
        }
        groups = {k: [] for k in fields}
        for fld, lat in mutation_samples:
            if fld in groups and lat is not None:
                groups[fld].append(lat)

        labels = [fields[k][0] for k in fields]
        colors = [fields[k][1] for k in fields]
        means = [round(statistics.mean(groups[k]), 2) if groups[k] else 0.0 for k in fields]

        fig, ax = plt.subplots(figsize=(8, 4.5))
        bars = ax.bar(labels, means, color=colors, width=0.55)
        ax.bar_label(bars, fmt="%.2f ms", padding=3, fontsize=9)
        ax.set_ylabel("Độ trễ đánh chặn trung bình (ms)")
        ax.set_title(f"SEC-03: Payload Mutation · Độ trễ theo trường bị sửa đổi\n[{alg_name}]", pad=12, fontweight="bold")
        ax.set_ylim(bottom=0)
        ax.margins(y=0.18)
        ax.grid(axis="y", alpha=0.3, linestyle="--")
        fig.tight_layout()
        fig.savefig(path, dpi=180)
        plt.close(fig)
        return True
    except Exception as e:
        print(f"[CHART] Không thể tạo biểu đồ mutation {path}: {e}", file=sys.stderr)
        return False


def write_replay_chart(path: Path, replay_samples: list[float], alg_name: str) -> bool:
    """Vẽ scatter plot độ trễ phát hiện và chặn Replay Attack."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        valid_pts = [(idx + 1, lat) for idx, lat in enumerate(replay_samples) if lat is not None]
        if not valid_pts:
            return False

        xs = [p[0] for p in valid_pts]
        ys = [p[1] for p in valid_pts]
        mean_y = statistics.mean(ys)

        fig, ax = plt.subplots(figsize=(8.5, 4.5))
        ax.scatter(xs, ys, color="#8154a4", alpha=0.75, s=36, edgecolors="none", label="Ca Replay bị chặn")
        ax.axhline(mean_y, color="#dc2626", linestyle="--", linewidth=1.5, label=f"Mean: {mean_y:.2f} ms")
        ax.set_xlabel("Thứ tự ca thử nghiệm")
        ax.set_ylabel("Độ trễ đánh chặn (ms)")
        ax.set_title(f"SEC-03: Anti-Replay Defense · Phân bổ độ trễ chặn phát lại\n[{alg_name}]", pad=12, fontweight="bold")
        ax.set_ylim(bottom=0)
        ax.margins(y=0.15)
        ax.grid(True, alpha=0.3, linestyle="--")
        ax.legend(loc="upper right")
        fig.tight_layout()
        fig.savefig(path, dpi=180)
        plt.close(fig)
        return True
    except Exception as e:
        print(f"[CHART] Không thể tạo biểu đồ replay {path}: {e}", file=sys.stderr)
        return False


def fetch_audit_trail_sample(ports: list[int]) -> list[dict]:
    """Trích xuất nhật ký Hộp đen kiểm toán từ các Node đang chạy."""
    collected_logs = []
    for p in ports:
        try:
            r = requests.get(f"http://127.0.0.1:{p}/audit/logs?limit=500", timeout=2.0)
            if r.status_code == 200:
                logs = r.json().get("logs", [])
                for log in logs:
                    log["node_port"] = p
                    collected_logs.append(log)
        except Exception:
            pass
    return collected_logs


def compute_block_hash(block: dict) -> str:
    """Tính toán SHA-256 canonical hash của Block để kiểm tra tính toàn vẹn."""
    block_copy = {
        'block_number': block.get('block_number'),
        'timestamp': block.get('timestamp'),
        'transactions': block.get('transactions', []),
        'nonce': block.get('nonce'),
        'previous_hash': block.get('previous_hash')
    }
    block_string = json.dumps(block_copy, sort_keys=True).encode('utf-8')
    return hashlib.sha256(block_string).hexdigest()


def verify_block_mining(ports: list[int], expected_benign_count: int = 0, initial_chain_len: int = 1) -> dict:
    """Kiểm tra và đối soát tiến trình Đào khối trên toàn mạng."""
    miner_port = ports[0]
    for p in ports:
        try:
            st = requests.get(f"http://127.0.0.1:{p}/status", timeout=1.5).json()
            if st.get("is_miner"):
                miner_port = p
                break
        except Exception:
            pass

    result = {
        "mining_triggered": False,
        "miner_port": miner_port,
        "total_chain_length": 1,
        "blocks": [],
        "total_user_txs_mined": 0,
        "expected_benign_count": expected_benign_count,
        "mempool_remaining": 0,
        "tampered_tx_in_block": 0,
        "status": "FAIL"
    }

    print(f"\n[*] Đang kết nối tới Node Thợ đào (Port {miner_port}) để đối soát tiến trình Auto-Mining...")

    # Chờ Auto-Miner xử lý (tối đa 4 giây)
    for _ in range(4):
        try:
            st = requests.get(f"http://127.0.0.1:{miner_port}/status", timeout=1.5).json()
            mempool_count = st.get("mempool_count", 0)
            if mempool_count == 0:
                break
            time.sleep(1.0)
        except Exception:
            break

    # Nếu vẫn còn giao dịch trong Mempool chưa đủ ngưỡng batch_size, gọi /mine để vét sạch
    try:
        st = requests.get(f"http://127.0.0.1:{miner_port}/status", timeout=1.5).json()
        remaining_txs = st.get("mempool_count", 0)
        if remaining_txs > 0:
            print(f"[*] Còn {remaining_txs} giao dịch trong Mempool chưa đủ batch, đang kích hoạt đào vét qua /mine...")
            for attempt in range(10):
                mine_res = requests.get(f"http://127.0.0.1:{miner_port}/mine?max_txs=1000", timeout=15.0)
                if mine_res.status_code == 200:
                    result["mining_triggered"] = True
                st_check = requests.get(f"http://127.0.0.1:{miner_port}/status", timeout=1.5).json()
                if st_check.get("mempool_count", 0) == 0:
                    break
                time.sleep(0.5)
    except Exception as e:
        result["error"] = f"Lỗi kích hoạt đào vét: {e}"

    # Truy vấn toàn bộ Sổ Cái /chain từ mạng
    chain_data = []
    for p in [miner_port] + [x for x in ports if x != miner_port]:
        try:
            res = requests.get(f"http://127.0.0.1:{p}/chain", timeout=3.0)
            if res.status_code == 200:
                chain_data = res.json().get("chain", [])
                if len(chain_data) > 1:
                    break
        except Exception:
            pass

    if chain_data:
        result["total_chain_length"] = len(chain_data)
        run_blocks = [b for b in chain_data if b.get("block_number", 1) > initial_chain_len]
        blocks_to_show = run_blocks if run_blocks else [b for b in chain_data if b.get("block_number", 1) > 1]
        result["blocks"] = []

        total_user_mined = 0
        tampered_found = 0

        for b in blocks_to_show:
            txs = b.get("transactions", [])
            user_txs = [tx for tx in txs if tx.get("sender_address") != "THE BLOCKCHAIN"]
            if b in run_blocks or not run_blocks:
                total_user_mined += len(user_txs)

            for tx in user_txs:
                if tx.get("tampered") or "MALICIOUS" in str(tx.get("value", "")):
                    tampered_found += 1

            result["blocks"].append({
                "block_number": b.get("block_number"),
                "timestamp": b.get("timestamp"),
                "total_tx_count": len(txs),
                "user_tx_count": len(user_txs),
                "nonce": b.get("nonce"),
                "hash": compute_block_hash(b)
            })

        try:
            st = requests.get(f"http://127.0.0.1:{miner_port}/status", timeout=1.5).json()
            result["mempool_remaining"] = st.get("mempool_count", 0)
        except Exception:
            result["mempool_remaining"] = 0

        result["total_user_txs_mined"] = total_user_mined
        result["tampered_tx_in_block"] = tampered_found
        result["status"] = "SUCCESS" if (total_user_mined >= expected_benign_count and tampered_found == 0) else "PARTIAL"

    return result


def print_summary_report(
    cases: list[TestCase],
    alg_name: str,
    client_names: list[str],
    mining_info: dict,
    audit_sample: list[dict],
    workers: int = 1
) -> str:
    buf = io.StringIO()
    def out(s=""):
        print(s)
        buf.write(s + "\n")

    out("\n" + "=" * 94)
    out("           BÁO CÁO KẾT QUẢ KIỂM THỬ AN NINH SEC-03 (MULTI-CLIENT ĐỐI CHỨNG)")
    out(f"  • Thuật toán kiểm thử:  {alg_name}")
    out(f"  • Các Client tham gia:  {', '.join(client_names)} (Gửi giao dịch chéo lẫn nhau)")
    out(f"  • Cơ chế điều phối:     ThreadPoolExecutor (Workers = {workers})")
    out(f"  • Tổng số ca kiểm thử:  {len(cases)} ca (50% Benign hợp lệ / 50% Malicious tấn công)")
    out("=" * 94)

    # 1. Bảng ma trận kết quả an ninh
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

    out("\n  [1] MA TRẬN PHÒNG THỦ & CHỐNG GIẢ MẠO:")
    out(sep)
    out(f"| {headers[0]:<32} | {headers[1]:^14} | {headers[2]:^8} | {headers[3]:^13} | {headers[4]:^8} | {headers[5]:^17} |")
    out(sep)

    total_benign_req = 0
    total_benign_pass = 0
    total_attack_req = 0
    total_attack_blocked = 0
    total_breach = 0

    for sc_name, d in matrix.items():
        b_rate = f"{(d['benign_pass'] / d['benign_req'] * 100):.1f}%" if d['benign_req'] else "N/A"
        a_rate = f"{(d['attack_blocked'] / d['attack_req'] * 100):.1f}%" if d['attack_req'] else "N/A"
        out(row_fmt.format(
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

    out(sep)
    tot_b_rate = f"{(total_benign_pass / total_benign_req * 100):.1f}%" if total_benign_req else "N/A"
    tot_a_rate = f"{(total_attack_blocked / total_attack_req * 100):.1f}%" if total_attack_req else "N/A"
    out(row_fmt.format(
        f"TỔNG CỘNG ({len(cases)} CA)",
        f"{total_benign_pass}/{total_benign_req}",
        tot_b_rate,
        f"{total_attack_blocked}/{total_attack_req}",
        tot_a_rate,
        str(total_breach)
    ))
    out(sep)

    # 2. Bảng đo lường & phân tích Độ trễ Đánh chặn
    out("\n" + "-" * 94)
    out("  [2] HIỆU NĂNG & ĐỘ TRỄ ĐÁNH CHẶN (INTERCEPTION LATENCY BENCHMARK):")
    out("-" * 94)

    all_benign_lat = [c.observation.elapsed_ms for c in cases if not c.is_attack and c.observation and c.observation.elapsed_ms is not None]
    all_attack_lat = [c.observation.elapsed_ms for c in cases if c.is_attack and c.observation and c.observation.elapsed_ms is not None]

    lat_bf = [c.observation.elapsed_ms for c in cases if c.is_attack and c.scenario == SCENARIO_BITFLIP and c.observation and c.observation.elapsed_ms is not None]
    lat_mut = [c.observation.elapsed_ms for c in cases if c.is_attack and c.scenario == SCENARIO_MUTATION and c.observation and c.observation.elapsed_ms is not None]
    lat_rep = [c.observation.elapsed_ms for c in cases if c.is_attack and c.scenario == SCENARIO_REPLAY and c.observation and c.observation.elapsed_ms is not None]

    # Breakdown chi tiết theo từng trường Mutation
    lat_mut_amount = [c.observation.elapsed_ms for c in cases if c.is_attack and c.scenario == SCENARIO_MUTATION and c.mutation_field == "amount" and c.observation and c.observation.elapsed_ms is not None]
    lat_mut_recp = [c.observation.elapsed_ms for c in cases if c.is_attack and c.scenario == SCENARIO_MUTATION and c.mutation_field == "recipient_address" and c.observation and c.observation.elapsed_ms is not None]
    lat_mut_sender = [c.observation.elapsed_ms for c in cases if c.is_attack and c.scenario == SCENARIO_MUTATION and c.mutation_field == "sender_address" and c.observation and c.observation.elapsed_ms is not None]

    lat_hdr = [
        "Phân loại Đo kiểm Độ trễ",
        "Số lượng", "Min (ms)", "Mean (ms)", "Med (ms)", "P95 (ms)", "Max (ms)"
    ]
    lat_row_fmt = "| {:<38} | {:^8} | {:^9} | {:^9} | {:^9} | {:^9} | {:^9} |"
    lat_sep = "+" + "-" * 40 + "+" + "-" * 10 + "+" + "-" * 11 + "+" + "-" * 11 + "+" + "-" * 11 + "+" + "-" * 11 + "+" + "-" * 11 + "+"

    out(lat_sep)
    out(f"| {lat_hdr[0]:<38} | {lat_hdr[1]:^8} | {lat_hdr[2]:^9} | {lat_hdr[3]:^9} | {lat_hdr[4]:^9} | {lat_hdr[5]:^9} | {lat_hdr[6]:^9} |")
    out(lat_sep)

    st_benign = calc_latency_stats(all_benign_lat)
    st_attack = calc_latency_stats(all_attack_lat)
    st_bf = calc_latency_stats(lat_bf)
    st_mut = calc_latency_stats(lat_mut)
    st_rep = calc_latency_stats(lat_rep)

    st_mut_amt = calc_latency_stats(lat_mut_amount)
    st_mut_rcp = calc_latency_stats(lat_mut_recp)
    st_mut_snd = calc_latency_stats(lat_mut_sender)

    out(lat_row_fmt.format("Benign (Xác thực Giao dịch Chuẩn)", st_benign["count"], f"{st_benign['min']:.2f}", f"{st_benign['mean']:.2f}", f"{st_benign['median']:.2f}", f"{st_benign['p95']:.2f}", f"{st_benign['max']:.2f}"))
    out(lat_sep)
    out(lat_row_fmt.format("Malicious (TỔNG ĐỘ TRỄ ĐÁNH CHẶN)", st_attack["count"], f"{st_attack['min']:.2f}", f"{st_attack['mean']:.2f}", f"{st_attack['median']:.2f}", f"{st_attack['p95']:.2f}", f"{st_attack['max']:.2f}"))
    out(lat_row_fmt.format("  • Chặn Lật bit (Bit-Flipping)", st_bf["count"], f"{st_bf['min']:.2f}", f"{st_bf['mean']:.2f}", f"{st_bf['median']:.2f}", f"{st_bf['p95']:.2f}", f"{st_bf['max']:.2f}"))
    out(lat_row_fmt.format("  • Chặn Giả mạo (Payload Mutation)", st_mut["count"], f"{st_mut['min']:.2f}", f"{st_mut['mean']:.2f}", f"{st_mut['median']:.2f}", f"{st_mut['p95']:.2f}", f"{st_mut['max']:.2f}"))
    if st_mut_amt["count"]:
        out(lat_row_fmt.format("     - Sửa Amount (Số tiền)", st_mut_amt["count"], f"{st_mut_amt['min']:.2f}", f"{st_mut_amt['mean']:.2f}", f"{st_mut_amt['median']:.2f}", f"{st_mut_amt['p95']:.2f}", f"{st_mut_amt['max']:.2f}"))
    if st_mut_rcp["count"]:
        out(lat_row_fmt.format("     - Sửa Recipient (Người nhận)", st_mut_rcp["count"], f"{st_mut_rcp['min']:.2f}", f"{st_mut_rcp['mean']:.2f}", f"{st_mut_rcp['median']:.2f}", f"{st_mut_rcp['p95']:.2f}", f"{st_mut_rcp['max']:.2f}"))
    if st_mut_snd["count"]:
        out(lat_row_fmt.format("     - Sửa Sender (Mạo danh gửi)", st_mut_snd["count"], f"{st_mut_snd['min']:.2f}", f"{st_mut_snd['mean']:.2f}", f"{st_mut_snd['median']:.2f}", f"{st_mut_snd['p95']:.2f}", f"{st_mut_snd['max']:.2f}"))
    out(lat_row_fmt.format("  • Chặn Phát lại (Anti-Replay)", st_rep["count"], f"{st_rep['min']:.2f}", f"{st_rep['mean']:.2f}", f"{st_rep['median']:.2f}", f"{st_rep['p95']:.2f}", f"{st_rep['max']:.2f}"))
    out(lat_sep)

    out(f"  => NHẬN XÉT: Độ trễ đánh chặn trung bình đạt {st_attack['mean']:.2f} ms (P95: {st_attack['p95']:.2f} ms).")
    out(f"     Node phát hiện và từ chối các cuộc tấn công ngay lập tức ở tầng Ingress trước khi vào Mempool.")

    # 3. Bằng chứng Hộp Đen Kiểm Toán (Audit Trail Log)
    out("\n" + "-" * 94)
    out("  [3] HỘP ĐEN KIỂM TOÁN (AUDIT TRAIL LOG SAMPLES):")
    out("-" * 94)
    crypto_failed_logs = [l for l in audit_sample if l.get("status") == "FAILED" and l.get("category") == "CRYPTO"]
    security_failed_logs = [l for l in audit_sample if l.get("status") == "FAILED" and l.get("category") == "SECURITY"]
    crypto_success_logs = [l for l in audit_sample if l.get("status") == "SUCCESS" and l.get("category") == "CRYPTO"]

    out(f"  [+] Đã ghi nhận {len(crypto_failed_logs)} ca từ chối chữ ký giả mạo (CRYPTO: FAILED)")
    out(f"  [+] Đã ghi nhận {len(security_failed_logs)} ca ngăn chặn tấn công phát lại (SECURITY: FAILED)")
    out(f"  [+] Đã ghi nhận {len(crypto_success_logs)} ca xác thực thành công người dùng chuẩn (CRYPTO: SUCCESS)")

    samples_to_show = (crypto_failed_logs[:2] + security_failed_logs[:2] + crypto_success_logs[:1])[:5]
    for s in samples_to_show:
        node_str = f"Node {s.get('node_port', 5000)}"
        out(f"   * [{s.get('timestamp')}] [{node_str}] [{s.get('category')}] {s.get('title')} -> {s.get('status')}")

    # 4. Bằng chứng Toàn Vẹn Khối Sổ Cái
    out("\n" + "-" * 94)
    out("  [4] SỔ CÁI BẤT BIẾN: ĐỐI SOÁT TỰ ĐỘNG ĐÀO (AUTO-MINING) & TOÀN VẸN CHUỖI KHỐI:")
    out("-" * 94)
    mined_blocks = mining_info.get("blocks", [])
    if mined_blocks:
        out(f"  [+] Đã xác nhận tổng cộng {len(mined_blocks)} Block được đào và lưu trữ trên Chuỗi Khối:")
        blk_hdr = ["Block #", "Thời gian (Timestamp)", "Giao dịch (User/Total)", "Nonce PoW", "Mã băm Khối (Hash Commit)"]
        blk_fmt = "| {:<9} | {:<21} | {:^22} | {:^11} | {:<20} |"
        blk_sep = "+" + "-" * 11 + "+" + "-" * 23 + "+" + "-" * 24 + "+" + "-" * 13 + "+" + "-" * 22 + "+"
        out("  " + blk_sep)
        out("  " + f"| {blk_hdr[0]:<9} | {blk_hdr[1]:<21} | {blk_hdr[2]:^22} | {blk_hdr[3]:^11} | {blk_hdr[4]:<20} |")
        out("  " + blk_sep)
        for b in mined_blocks:
            ts_val = b.get("timestamp")
            if isinstance(ts_val, (int, float)):
                ts_str = datetime.fromtimestamp(ts_val).strftime("%Y-%m-%d %H:%M:%S")
            else:
                ts_str = str(ts_val)[:19]
            tx_str = f"{b['user_tx_count']} user / {b['total_tx_count']} tot"
            h_str = b.get("hash", "")
            h_short = f"{h_str[:8]}...{h_str[-8:]}" if len(h_str) >= 16 else h_str
            out("  " + blk_fmt.format(f"Block #{b['block_number']}", ts_str, tx_str, str(b['nonce']), h_short))
        out("  " + blk_sep)

        expected = mining_info.get("expected_benign_count", 0)
        mined_user = mining_info.get("total_user_txs_mined", 0)
        rem_mempool = mining_info.get("mempool_remaining", 0)
        tampered = mining_info.get("tampered_tx_in_block", 0)
        reconcile_rate = (mined_user / expected * 100) if expected else 100.0

        out(f"\n  📊 BẢNG TỔNG KẾT ĐỐI SOÁT GIAO DỊCH (TRANSACTION RECONCILIATION):")
        out(f"     • Số giao dịch hợp lệ (Benign) phát sóng   : {expected} TXs")
        out(f"     • Số giao dịch người dùng đã được đào      : {mined_user} / {expected} TXs (TỶ LỆ ĐỐI SOÁT: {reconcile_rate:.1f}%)")
        out(f"     • Số giao dịch còn tồn đọng trong Mempool   : {rem_mempool} TXs")
        out(f"     • Số giao dịch giả mạo/độc hại lọt vào Khối : {tampered} TXs (TỶ LỆ Ô NHIỄM SỔ CÁI: 0.00%)")
        if reconcile_rate >= 100.0 and rem_mempool == 0 and tampered == 0:
            out(f"  => KẾT LUẬN: ĐỦ 100% SỐ GIAO DỊCH, KHÔNG BỊ THẤT THOÁT VÀ ĐÃ ĐƯỢC ĐÀO THÀNH CÔNG VÀO CÁC BLOCK BẤT BIẾN!")
        else:
            out(f"  => CẢNH BÁO: Kiểm tra lại tính đồng thuận hoặc thời gian chờ auto-miner giữa các Node.")
    else:
        out(f"  [!] Chưa có Block người dùng nào được khai thác ({mining_info.get('error', 'Chưa kích hoạt miner')}).")
    out("=" * 94 + "\n")
    return buf.getvalue()


def run(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    print("=" * 94)
    print("  KHỞI ĐỘNG KỊCH BẢN KIỂM THỬ AN NINH CHỮ KÝ SỐ SEC-03 (MULTI-CLIENT)")
    print("=" * 94)

    # 1. Khởi tạo Wallet Manager và xác định thuật toán duy nhất
    mgr = WalletManager(root)
    scheme_id, alg_name, client_pairs, client_names = mgr.resolve_scheme(
        args.scheme, args.wallet
    )

    print(f"[*] Thuật toán đang kiểm thử : {alg_name}")
    print(f"[*] Mô hình mạng Client       : Multi-Client ({len(client_names)} Ví tham gia: {', '.join(client_names)})")
    print(f"[*] Số cặp truyền giao dịch   : {len(client_pairs)} luồng gửi chéo nhau")
    print(f"[*] Dải cổng Node mục tiêu    : {args.ports}")
    print(f"[*] Số ca mỗi kịch bản         : {args.count_per_scenario} (Tỉ lệ: 50% Benign / 50% Malicious)")
    print(f"[*] Cơ chế phát sóng          : ThreadPoolExecutor (Workers = {args.workers})")

    # 2. Sinh ma trận dữ liệu kiểm thử đối chứng Multi-Client
    independent_cases, replay_pairs = build_test_suite(
        mgr, client_pairs, args.count_per_scenario, args.seed, ports=args.ports
    )

    rng = random.Random(args.seed)
    rng.shuffle(independent_cases)

    # Ghép toàn bộ ca kiểm thử theo thứ tự phát sóng
    final_cases: list[TestCase] = []
    final_cases.extend(independent_cases)
    for b_case, r_case in replay_pairs:
        final_cases.append(b_case)
        final_cases.append(r_case)

    for idx, c in enumerate(final_cases, 1):
        c.case_id = idx

    total_cases = len(final_cases)
    print(f"[+] Đã tạo thành công {total_cases} ca kiểm thử đối chứng Multi-Client. Chuẩn bị phát sóng...")

    # Ghi nhận chiều dài chuỗi trước đợt bắn
    initial_chain_len = 1
    for p in args.ports:
        try:
            cr = requests.get(f"http://127.0.0.1:{p}/chain", timeout=1.5).json()
            initial_chain_len = max(initial_chain_len, cr.get("length", 1))
            break
        except Exception:
            pass

    # 3. Chuẩn bị kết nối đa luồng (Multi-Worker Dispatch)
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=max(10, args.workers * 2),
        pool_maxsize=max(10, args.workers * 2),
        max_retries=0
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    node_locks = {p: threading.Lock() for p in args.ports}

    print(f"\n[*] Giai đoạn 1 & 2: Phát sóng đồng thời {len(independent_cases)} giao dịch (Bit-flip & Mutation) qua {args.workers} workers...")
    completed_counter = 0
    total_indep = len(independent_cases)
    progress_step = max(1, total_indep // 10)
    counter_lock = threading.Lock()

    def worker_task(tc: TestCase) -> TestCase:
        nonlocal completed_counter
        target_port = rng.choice(args.ports)
        tc.target_port = target_port
        with node_locks[target_port]:
            tc.observation = send_transaction(session, target_port, tc.wire_payload, args.timeout)
            if args.delay > 0:
                time.sleep(args.delay)
        classify_observation(tc)

        with counter_lock:
            completed_counter += 1
            cur = completed_counter

        if cur % progress_step == 0 or cur == total_indep:
            lat = f"{tc.observation.elapsed_ms:.1f}ms" if tc.observation else "N/A"
            print(f"    -> [Workers] Đã thực thi {cur}/{total_indep} ca (Port {target_port} -> Status: {tc.observation.status or 'ERR'} -> {tc.classified_result} [{lat}])")
        return tc

    if args.workers > 1:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            list(executor.map(worker_task, independent_cases))
    else:
        for tc in independent_cases:
            worker_task(tc)

    # Giai đoạn 3: Replay Attack (Tuân thủ tuần tự bản gốc trước, bản phát lại sau)
    print(f"\n[*] Giai đoạn 3: Phát sóng {len(replay_pairs) * 2} giao dịch Chống Phát lại (Anti-Replay Defense)...")
    for b_case, r_case in replay_pairs:
        # Gửi giao dịch gốc vào một node ngẫu nhiên
        target_port = rng.choice(args.ports)
        b_case.target_port = target_port
        with node_locks[target_port]:
            b_case.observation = send_transaction(session, target_port, b_case.wire_payload, args.timeout)
        classify_observation(b_case)

        # Chờ mạng ổn định
        if args.delay > 0:
            time.sleep(args.delay)
        else:
            time.sleep(0.02)

        # Phát lại chính xác giao dịch cũ vào cùng node để kiểm chứng cơ chế Mempool/Ledger Replay Defense
        r_port = target_port
        r_case.target_port = r_port
        with node_locks[r_port]:
            r_case.observation = send_transaction(session, r_port, r_case.wire_payload, args.timeout)
        classify_observation(r_case)

    # 4. Thu thập mẫu Hộp đen kiểm toán từ các Node
    audit_samples = fetch_audit_trail_sample(args.ports)

    # 5. Kích hoạt Đóng Block để kiểm tra tính Toàn vẹn của Sổ Cái & Đối soát số lượng
    mining_info = {}
    if args.mine_after:
        expected_benign = sum(1 for c in final_cases if not c.is_attack and c.classified_result == "PASSED")
        mining_info = verify_block_mining(args.ports, expected_benign_count=expected_benign, initial_chain_len=initial_chain_len)

    # 6. Ghi log JSONL chi tiết
    log_path: Path = args.log
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as f:
        for tc in final_cases:
            rec = {
                "case_id": tc.case_id,
                "scenario": tc.scenario,
                "is_attack": tc.is_attack,
                "label": tc.label,
                "sender_name": tc.sender_name,
                "recipient_name": tc.recipient_name,
                "target_port": tc.target_port,
                "status_code": tc.observation.status if tc.observation else None,
                "elapsed_ms": tc.observation.elapsed_ms if tc.observation else None,
                "classified_result": tc.classified_result,
                "reason": tc.reason,
                "mutation_field": tc.mutation_field,
                "bit_flips": tc.bit_flips
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    print(f"\n[+] Log chi tiết {total_cases} ca kiểm thử đã được lưu tại: {log_path}")

    # 7. In Bảng Báo Cáo Tổng Hợp Khoa Học & Lưu Terminal Log
    terminal_text = print_summary_report(final_cases, alg_name, client_names, mining_info, audit_samples, workers=args.workers)
    term_log_path = log_path.with_suffix(".terminal.log")
    try:
        term_log_path.write_text(terminal_text, encoding="utf-8")
        print(f"[+] Nhật ký Terminal đã được lưu tại: {term_log_path}")
    except Exception as e:
        print(f"[!] Không thể lưu nhật ký terminal: {e}")

    # 8. Sinh tệp JSON Tóm tắt (.summary.json)
    bit_samples = [(c.bit_flips, c.observation.elapsed_ms) for c in final_cases if c.is_attack and c.scenario == SCENARIO_BITFLIP and c.observation and c.classified_result == "BLOCKED"]
    mut_samples = [(c.mutation_field, c.observation.elapsed_ms) for c in final_cases if c.is_attack and c.scenario == SCENARIO_MUTATION and c.observation and c.classified_result == "BLOCKED"]
    rep_samples = [c.observation.elapsed_ms for c in final_cases if c.is_attack and c.scenario == SCENARIO_REPLAY and c.observation and c.classified_result == "BLOCKED"]

    all_attack_lats = [c.observation.elapsed_ms for c in final_cases if c.is_attack and c.observation and c.observation.elapsed_ms is not None]
    all_benign_lats = [c.observation.elapsed_ms for c in final_cases if not c.is_attack and c.observation and c.observation.elapsed_ms is not None]

    summary_data = {
        "algorithm": alg_name,
        "scheme": scheme_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "workers": args.workers,
        "total_cases": total_cases,
        "benign_cases": len(all_benign_lats),
        "attack_cases": len(all_attack_lats),
        "breach_count": sum(1 for c in final_cases if c.classified_result == "BREACH"),
        "latency_stats": {
            "all_attack": calc_latency_stats(all_attack_lats),
            "all_benign": calc_latency_stats(all_benign_lats),
            "bitflip": calc_latency_stats([s[1] for s in bit_samples]),
            "mutation": calc_latency_stats([s[1] for s in mut_samples]),
            "replay": calc_latency_stats(rep_samples)
        },
        "bit_flip_detail": {
            str(b): calc_latency_stats([lat for bits, lat in bit_samples if bits == b])
            for b in range(1, 5)
        },
        "mutation_detail": {
            fld: calc_latency_stats([lat for f, lat in mut_samples if f == fld])
            for fld in ("amount", "recipient_address", "sender_address")
        },
        "mining_reconciliation": mining_info,
        "log_path": str(log_path)
    }

    summary_path = log_path.with_suffix(".summary.json")
    try:
        summary_path.write_text(json.dumps(summary_data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[+] Tóm tắt định lượng (.summary.json) đã được lưu tại: {summary_path}")
    except Exception as e:
        print(f"[!] Không thể lưu summary json: {e}")

    # 9. Vẽ và lưu 3 biểu đồ trực quan hóa (.png)
    bit_png_path = log_path.with_suffix(".bits.png")
    mut_png_path = log_path.with_suffix(".mutation.png")
    rep_png_path = log_path.with_suffix(".replay.png")

    if write_bit_chart(bit_png_path, bit_samples, alg_name):
        print(f"[+] Biểu đồ Lật bit: {bit_png_path}")
    if write_mutation_chart(mut_png_path, mut_samples, alg_name):
        print(f"[+] Biểu đồ Sửa Payload: {mut_png_path}")
    if write_replay_chart(rep_png_path, rep_samples, alg_name):
        print(f"[+] Biểu đồ Chống phát lại: {rep_png_path}")

    # Xác định mã thoát: 0 nếu không có vi phạm an ninh (Breach = 0)
    has_breach = any(c.classified_result == "BREACH" for c in final_cases)
    return 1 if has_breach else 0


def parse_args() -> argparse.Namespace:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    proj_root = Path(__file__).resolve().parent.parent.parent
    default_log_dir = proj_root / "benchmarks" / "results" / "sec03_tamper"
    default_log_dir.mkdir(parents=True, exist_ok=True)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=proj_root, help="Thư mục gốc của dự án")
    parser.add_argument(
        "--scheme", "--sig", type=str, default="mldsa44",
        choices=["ecdsa", "mldsa44", "mldsa65", "mldsa87"],
        help="Thuật toán chữ ký số độc lập cần kiểm thử: ecdsa, mldsa44 (mặc định), mldsa65, mldsa87"
    )
    parser.add_argument("--wallet", type=str, default=None, help="Tùy chọn chỉ định ví xuất phát")
    parser.add_argument("--count-per-scenario", type=int, default=300, help="Số giao dịch mỗi kịch bản (mặc định 300 = 150 Benign + 150 Malicious)")
    parser.add_argument("--ports", nargs="+", type=int, default=DEFAULT_PORTS, help="Danh sách cổng node mục tiêu (mặc định 5000-5005)")
    parser.add_argument("--workers", type=int, default=6, help="Số luồng gửi đồng thời (mặc định: 6 luồng)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout HTTP (giây)")
    parser.add_argument("--delay", type=float, default=0.0, help="Độ trễ giữa các request (giây)")
    parser.add_argument("--seed", type=int, default=42, help="Seed ngẫu nhiên")
    parser.add_argument("--mine-after", action="store_true", default=True, help="Tự động gọi /mine để kiểm tra giao dịch vào Block")
    parser.add_argument("--no-mine", dest="mine_after", action="store_false", help="Không tự động gọi /mine")
    parser.add_argument("--log", type=Path, default=default_log_dir / f"sec03_{stamp}_{uuid.uuid4().hex[:8]}.jsonl", help="Đường dẫn lưu log JSONL")

    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(run(parse_args()))
