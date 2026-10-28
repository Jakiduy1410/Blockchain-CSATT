import argparse
import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
BENCH_DIR = ROOT / "benchmarks"
RESULT_DIR = BENCH_DIR / "results"
WALLETS_PATH = ROOT / "configs" / "wallets.json"

sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(BENCH_DIR))

from macro_benchmark import create_signed_ecdsa_transaction
from blockchain.core.crypto import calculate_block_hash


def create_net_transaction(sender, recipient_pubkey, amount, nonce=1):
    """
    Tao transaction dung voi verifier cua repo:
    - ECDSA: ky sender + recipient + value + nonce
    - ML-DSA-44: ky sender + recipient + value
    """
    pub = sender.get("public_key", "")

    if len(pub) < 1000:
        return create_signed_ecdsa_transaction(
            sender,
            recipient_pubkey,
            amount,
            nonce
        )

    from collections import OrderedDict
    import oqs

    tx_dict = OrderedDict([
        ("sender_address", sender["public_key"]),
        ("recipient_address", recipient_pubkey),
        ("value", str(amount))
    ])

    tx_bytes = str(tx_dict).encode("utf-8")
    priv_bytes = bytes.fromhex(sender["private_key"])

    with oqs.Signature(
        "ML-DSA-44",
        secret_key=priv_bytes
    ) as signer:
        sig_bytes = signer.sign(tx_bytes)

    return {
        "sender_address": sender["public_key"],
        "recipient_address": recipient_pubkey,
        "amount": str(amount),
        "nonce": nonce,
        "signature": sig_bytes.hex()
    }


NODE1 = "http://127.0.0.1:5000"
NODE2 = "http://127.0.0.1:5001"

MLDSA_WALLET_NAME = "NET_MLDSA"
RESULT_CSV = RESULT_DIR / "net01_net02_results.csv"
SUMMARY_CSV = RESULT_DIR / "net01_net02_summary.csv"


def load_wallets():
    with open(WALLETS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def save_wallets(wallets):
    with open(WALLETS_PATH, "w", encoding="utf-8") as f:
        json.dump(wallets, f, indent=4, ensure_ascii=False)


def prepare_mldsa_wallet():
    """
    Sinh ví ML-DSA-44 test thật và thêm vào configs/wallets.json.
    Chỉ sinh một lần. Nếu đã có thì giữ nguyên.
    """
    wallets = load_wallets()

    if MLDSA_WALLET_NAME in wallets:
        w = wallets[MLDSA_WALLET_NAME]

        print("[+] Vi ML-DSA test da ton tai.")
        print(f"    Public key bytes : {len(w['public_key']) // 2}")
        print(f"    Secret key bytes : {len(w['private_key']) // 2}")
        print(f"    Initial balance  : {w.get('initial_balance', 0)}")
        return

    import oqs

    print("[*] Dang sinh keypair ML-DSA-44 that...")

    with oqs.Signature("ML-DSA-44") as signer:
        public_key = signer.generate_keypair()
        private_key = signer.export_secret_key()

    wallets[MLDSA_WALLET_NAME] = {
        "name": "NET01 NET02 ML-DSA Test Wallet",
        "initial_balance": 1000.0,
        "private_key": private_key.hex(),
        "public_key": public_key.hex()
    }

    save_wallets(wallets)

    print("[+] Da them vi ML-DSA vao configs/wallets.json")
    print(f"    Public key bytes : {len(public_key)}")
    print(f"    Secret key bytes : {len(private_key)}")
    print("    Initial balance  : 1000 COIN")
    print()
    print("[!] CAN RESTART NETWORK de cac node nap initial_balance moi.")


def get_status(url):
    r = requests.get(f"{url}/status", timeout=5)
    r.raise_for_status()
    return r.json()


def get_chain(url):
    r = requests.get(f"{url}/chain", timeout=5)
    r.raise_for_status()
    return r.json()["chain"]


def chain_tip_hash(url):
    chain = get_chain(url)

    if not chain:
        return ""

    return calculate_block_hash(chain[-1])


def get_next_nonce(sender_pubkey):
    """
    Tính nonce tiếp theo từ blockchain + mempool Node1.
    Cho phép chạy script lại mà không bị nonce trùng.
    """
    max_nonce = 0

    chain = get_chain(NODE1)

    for block in chain:
        for tx in block.get("transactions", []):
            if tx.get("sender_address") == sender_pubkey:
                try:
                    max_nonce = max(max_nonce, int(tx.get("nonce", 0)))
                except Exception:
                    pass

    status = get_status(NODE1)

    for tx in status.get("mempool", []):
        if tx.get("sender_address") == sender_pubkey:
            try:
                max_nonce = max(max_nonce, int(tx.get("nonce", 0)))
            except Exception:
                pass

    return max_nonce + 1


def wait_tx_propagation(signature, timeout=5.0):
    """
    Chờ transaction từ Node1 gossip sang Node2.
    """
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            status = get_status(NODE2)

            for tx in status.get("mempool", []):
                if tx.get("signature") == signature:
                    return True

        except Exception:
            pass

        time.sleep(0.05)

    return False


def wait_chain_sync(timeout=5.0):
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            c1 = get_chain(NODE1)
            c2 = get_chain(NODE2)

            if (
                len(c1) == len(c2)
                and calculate_block_hash(c1[-1])
                == calculate_block_hash(c2[-1])
            ):
                return True

        except Exception:
            pass

        time.sleep(0.1)

    return False


def send_tx(tx):
    r = requests.post(
        f"{NODE1}/transactions/new",
        json=tx,
        timeout=10
    )

    return r.status_code, r.text


def mine_node(url):
    t0 = time.perf_counter()

    try:
        r = requests.get(
            f"{url}/mine",
            timeout=30
        )

        dt_ms = (
            time.perf_counter() - t0
        ) * 1000.0

        return {
            "status": r.status_code,
            "time_ms": dt_ms,
            "text": r.text
        }

    except Exception as e:
        dt_ms = (
            time.perf_counter() - t0
        ) * 1000.0

        return {
            "status": 0,
            "time_ms": dt_ms,
            "text": str(e)
        }


def concurrent_mine():
    """
    Kích hoạt Node1 và Node2 đào gần đồng thời.
    """
    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(mine_node, NODE1)
        f2 = executor.submit(mine_node, NODE2)

        return f1.result(), f2.result()


def get_metric_samples(url):
    status = get_status(url)

    metrics = status.get(
        "net_metrics",
        {}
    )

    return metrics


def choose_wallets(algorithm):
    wallets = load_wallets()

    if algorithm == "ML-DSA":
        if MLDSA_WALLET_NAME not in wallets:
            raise RuntimeError(
                "Chua co vi NET_MLDSA. "
                "Hay chay prepare-wallet truoc."
            )

        sender = wallets[MLDSA_WALLET_NAME]

        recipient = None

        for name, wallet in wallets.items():
            if (
                name != MLDSA_WALLET_NAME
                and len(wallet.get("public_key", "")) < 1000
            ):
                recipient = wallet
                break

        if recipient is None:
            raise RuntimeError(
                "Khong tim thay vi ECDSA recipient."
            )

        return sender, recipient

    # ECDSA
    ecdsa_wallets = [
        wallet
        for name, wallet in wallets.items()
        if (
            name != MLDSA_WALLET_NAME
            and len(wallet.get("public_key", "")) < 1000
        )
    ]

    if len(ecdsa_wallets) < 2:
        raise RuntimeError(
            "Can it nhat 2 vi ECDSA."
        )

    return ecdsa_wallets[0], ecdsa_wallets[1]


def append_rows(rows):
    RESULT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    exists = RESULT_CSV.exists()

    fields = [
        "timestamp",
        "label",
        "algorithm",
        "round",
        "tx_json_bytes",
        "public_key_bytes",
        "signature_bytes",
        "tx_propagated_to_node2",
        "node1_mine_status",
        "node2_mine_status",
        "node1_mining_ms",
        "node2_mining_ms",
        "fork_detected",
        "chain_length_node1",
        "chain_length_node2",
        "propagation_ms_node2"
    ]

    with open(
        RESULT_CSV,
        "a",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )

        if not exists:
            writer.writeheader()

        writer.writerows(rows)


def append_summary(row):
    RESULT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    exists = SUMMARY_CSV.exists()

    fields = [
        "timestamp",
        "label",
        "algorithm",
        "rounds",
        "fork_rounds",
        "fork_rate_percent",
        "resolve_conflicts_delta",
        "conflict_delta",
        "fork_counter_delta",
        "orphan_blocks_delta",
        "propagation_samples",
        "avg_propagation_ms",
        "min_propagation_ms",
        "max_propagation_ms",
        "avg_tx_json_bytes"
    ]

    with open(
        SUMMARY_CSV,
        "a",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )

        if not exists:
            writer.writeheader()

        writer.writerow(row)


def metric_delta(after, before, key):
    return (
        int(after.get(key, 0))
        -
        int(before.get(key, 0))
    )


def run_experiment(algorithm, rounds, label):
    print("=" * 70)
    print("NET-01 / NET-02 BLOCKCHAIN NETWORK EXPERIMENT")
    print("=" * 70)
    print(f"Algorithm : {algorithm}")
    print(f"Rounds    : {rounds}")
    print(f"Label     : {label}")
    print()

    # Check network.
    s1 = get_status(NODE1)
    s2 = get_status(NODE2)

    print(
        f"[+] Node1 online | "
        f"chain={s1['chain_length']}"
    )

    print(
        f"[+] Node2 online | "
        f"chain={s2['chain_length']}"
    )

    sender, recipient = choose_wallets(
        algorithm
    )

    nonce = get_next_nonce(
        sender["public_key"]
    )

    before1 = get_metric_samples(NODE1)
    before2 = get_metric_samples(NODE2)

    node2_sample_start = len(
        before2.get(
            "block_propagation_delays_ms",
            []
        )
    )

    rows = []
    fork_rounds = 0

    for round_no in range(
        1,
        rounds + 1
    ):
        print()
        print(
            f"[*] ROUND {round_no}/{rounds}"
        )

        # ----------------------------------------------------------
        # Transaction dùng cho block cạnh tranh.
        # ----------------------------------------------------------

        tx = create_net_transaction(
            sender,
            recipient["public_key"],
            "0.01",
            nonce=nonce
        )

        nonce += 1

        tx_json_bytes = len(
            json.dumps(
                tx,
                separators=(",", ":")
            ).encode("utf-8")
        )

        public_key_bytes = (
            len(sender["public_key"]) // 2
        )

        signature_bytes = (
            len(tx["signature"]) // 2
        )

        code, text = send_tx(tx)

        if code not in (200, 201):
            raise RuntimeError(
                f"Transaction bi reject: "
                f"HTTP {code}\n{text}"
            )

        propagated = wait_tx_propagation(
            tx["signature"]
        )

        print(
            f"    TX bytes={tx_json_bytes} | "
            f"gossip Node2={propagated}"
        )

        # Metric trước mining round.
        metric_before_round = (
            get_metric_samples(NODE2)
        )

        old_sample_count = len(
            metric_before_round.get(
                "block_propagation_delays_ms",
                []
            )
        )

        # ----------------------------------------------------------
        # Node1 và Node2 mine cạnh tranh.
        # ----------------------------------------------------------

        mine1, mine2 = concurrent_mine()

        time.sleep(0.4)

        chain1 = get_chain(NODE1)
        chain2 = get_chain(NODE2)

        tip1 = calculate_block_hash(
            chain1[-1]
        )

        tip2 = calculate_block_hash(
            chain2[-1]
        )

        fork_detected = (
            len(chain1) == len(chain2)
            and tip1 != tip2
        )

        if fork_detected:
            fork_rounds += 1

        metric_after_compete = (
            get_metric_samples(NODE2)
        )

        samples_now = (
            metric_after_compete.get(
                "block_propagation_delays_ms",
                []
            )
        )

        if len(samples_now) > old_sample_count:
            propagation_ms = (
                samples_now[-1]
            )
        else:
            propagation_ms = 0.0

        print(
            f"    Node1 mine={mine1['status']} | "
            f"Node2 mine={mine2['status']} | "
            f"fork={fork_detected} | "
            f"propagation={propagation_ms:.3f} ms"
        )

        rows.append({
            "timestamp": time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "label": label,
            "algorithm": algorithm,
            "round": round_no,
            "tx_json_bytes": tx_json_bytes,
            "public_key_bytes":
                public_key_bytes,
            "signature_bytes":
                signature_bytes,
            "tx_propagated_to_node2":
                propagated,
            "node1_mine_status":
                mine1["status"],
            "node2_mine_status":
                mine2["status"],
            "node1_mining_ms":
                round(
                    mine1["time_ms"],
                    3
                ),
            "node2_mining_ms":
                round(
                    mine2["time_ms"],
                    3
                ),
            "fork_detected":
                fork_detected,
            "chain_length_node1":
                len(chain1),
            "chain_length_node2":
                len(chain2),
            "propagation_ms_node2":
                round(
                    propagation_ms,
                    6
                )
        })

        # ----------------------------------------------------------
        # Tie-break block:
        # Node1 mine thêm 1 block để longest-chain resolution.
        # Nếu trước đó có fork thì chain thua sẽ trở thành orphan.
        # ----------------------------------------------------------

        tie_tx = create_net_transaction(
            sender,
            recipient["public_key"],
            "0.01",
            nonce=nonce
        )

        nonce += 1

        tie_code, tie_text = send_tx(
            tie_tx
        )

        if tie_code not in (200, 201):
            raise RuntimeError(
                f"Tie-break TX bi reject: "
                f"HTTP {tie_code}\n"
                f"{tie_text}"
            )

        wait_tx_propagation(
            tie_tx["signature"]
        )

        mine_node(NODE1)

        synced = wait_chain_sync(
            timeout=5.0
        )

        print(
            f"    Reconcile sync={synced}"
        )

    # --------------------------------------------------------------
    # Kết quả cuối.
    # --------------------------------------------------------------

    append_rows(rows)

    after1 = get_metric_samples(NODE1)
    after2 = get_metric_samples(NODE2)

    samples_after = after2.get(
        "block_propagation_delays_ms",
        []
    )

    new_samples = samples_after[
        node2_sample_start:
    ]

    if new_samples:
        avg_prop = (
            sum(new_samples)
            /
            len(new_samples)
        )

        min_prop = min(new_samples)
        max_prop = max(new_samples)

    else:
        avg_prop = 0.0
        min_prop = 0.0
        max_prop = 0.0

    avg_tx_size = (
        sum(
            row["tx_json_bytes"]
            for row in rows
        )
        /
        len(rows)
        if rows
        else 0.0
    )

    summary = {
        "timestamp": time.strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "label": label,
        "algorithm": algorithm,
        "rounds": rounds,
        "fork_rounds":
            fork_rounds,
        "fork_rate_percent":
            round(
                fork_rounds
                / rounds
                * 100.0,
                3
            )
            if rounds
            else 0.0,
        "resolve_conflicts_delta":
            metric_delta(
                after2,
                before2,
                "resolve_conflicts_count"
            ),
        "conflict_delta":
            metric_delta(
                after2,
                before2,
                "conflict_count"
            ),
        "fork_counter_delta":
            metric_delta(
                after2,
                before2,
                "fork_count"
            ),
        "orphan_blocks_delta":
            metric_delta(
                after2,
                before2,
                "orphan_blocks_count"
            ),
        "propagation_samples":
            len(new_samples),
        "avg_propagation_ms":
            round(avg_prop, 6),
        "min_propagation_ms":
            round(min_prop, 6),
        "max_propagation_ms":
            round(max_prop, 6),
        "avg_tx_json_bytes":
            round(avg_tx_size, 3)
    }

    append_summary(summary)

    print()
    print("=" * 70)
    print("KET QUA")
    print("=" * 70)

    for key, value in summary.items():
        print(
            f"{key:28}: {value}"
        )

    print()
    print(
        f"[+] Raw CSV: {RESULT_CSV}"
    )

    print(
        f"[+] Summary: {SUMMARY_CSV}"
    )


def main():
    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(
        dest="command",
        required=True
    )

    sub.add_parser(
        "prepare-wallet"
    )

    run_parser = sub.add_parser(
        "run"
    )

    run_parser.add_argument(
        "--algorithm",
        required=True,
        choices=[
            "ECDSA",
            "ML-DSA"
        ]
    )

    run_parser.add_argument(
        "--rounds",
        type=int,
        default=5
    )

    run_parser.add_argument(
        "--label",
        default="baseline"
    )

    args = parser.parse_args()

    if args.command == "prepare-wallet":
        prepare_mldsa_wallet()
        return

    if args.command == "run":
        run_experiment(
            args.algorithm,
            args.rounds,
            args.label
        )


if __name__ == "__main__":
    main()
