#!/usr/bin/env python3
"""Khởi động lần lượt 5 mạng SEC-03, chạy kiểm thử và so sánh độ trễ."""

from __future__ import annotations

import argparse
import json
import math
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path

from compare import PROJECTS, analyze_logs, report_batch
from sec03_wallets import provision_mldsa_wallets
from tests.sec03_signature_integrity.prepare_runtime import prepare_runtime

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def network_config(project):
    path = project / "configs" / "network_6nodes.json"
    if not path.is_file():
        path = project / "network_6nodes.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    nodes = data["nodes"]
    ports = [int(node["port"]) for node in nodes]
    miners = [int(node["port"]) for node in nodes
              if node.get("is_miner")]
    if len(ports) != len(set(ports)) or len(miners) != 1:
        raise ValueError(f"Cấu hình cổng/miner không hợp lệ: {path}")
    return nodes, ports, miners[0]


def port_available(port):
    with socket.socket() as connection:
        connection.settimeout(0.25)
        return connection.connect_ex(("127.0.0.1", port)) != 0


def wait_ready(ports, processes, timeout):
    deadline = time.monotonic() + timeout
    pending = set(ports)
    while pending and time.monotonic() < deadline:
        for port, process in processes.items():
            if process.poll() is not None:
                raise RuntimeError(
                    f"Node {port} dừng sớm (exit={process.returncode})"
                )
        for port in list(pending):
            try:
                with OPENER.open(
                    f"http://127.0.0.1:{port}/status", timeout=0.7
                ) as response:
                    if response.status == 200:
                        pending.remove(port)
            except (urllib.error.URLError, TimeoutError, OSError):
                pass
        if pending:
            time.sleep(0.25)
    if pending:
        raise TimeoutError(f"Node chưa sẵn sàng: {sorted(pending)}")


def wait_funded(ports, sender_address, timeout, minimum=22.0):
    """Require the exact, full public key and funded balance on every node."""
    deadline = time.monotonic() + timeout
    pending = set(ports)
    balances = {}
    while pending and time.monotonic() < deadline:
        for port in list(pending):
            try:
                with OPENER.open(
                    f"http://127.0.0.1:{port}/accounts/balance",
                    timeout=1.0,
                ) as response:
                    body = json.load(response)
                records = body.get("balances", [])
                match = next(
                    (record for record in records
                     if record.get("address") == sender_address),
                    None,
                )
                if match is None:
                    continue
                balance = float(match["available_balance"])
                if math.isfinite(balance) and balance >= minimum:
                    balances[port] = balance
                    pending.remove(port)
            except (urllib.error.URLError, OSError, ValueError,
                    TypeError, KeyError, AttributeError):
                pass
        if pending:
            time.sleep(0.25)
    if pending:
        raise RuntimeError(
            "/accounts/balance không tìm thấy ví đúng public key "
            f"với >= {minimum} coin trên các node {sorted(pending)}"
        )
    return balances


def stop_nodes(processes):
    for process in processes.values():
        if process.poll() is None:
            process.terminate()
    for process in processes.values():
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run_project(algorithm, directory, args, run_id, pending_outputs=None):
    project = ROOT / directory
    nodes, ports, miner_port = network_config(project)
    attack_file = project / "attack_sec03.py"
    if not attack_file.is_file():
        raise FileNotFoundError(attack_file)

    log_path = project / f"sec03_{run_id}.jsonl"
    command = [
        args.python, str(attack_file),
        "--project-root", str(project),
        "--host", "127.0.0.1",
        "--ports", *(str(port) for port in ports),
        "--miner-port", str(miner_port),
        "--confirm-timeout", str(args.confirm_timeout),
        "--settle", str(args.settle),
        "--delay", str(args.delay),
        "--workers", str(args.workers),
        "--seed", str(args.seed),
        "--log", str(log_path),
    ]
    result = {"algorithm": algorithm, "project": str(project),
              "log": str(log_path), "node_logs": {}, "exit_code": None}
    if args.dry_run:
        print(f"[DRY RUN] {algorithm}: {len(nodes)} node, miner={miner_port}")
        if algorithm in {"ML-DSA-65", "ML-DSA-87"}:
            print("  Sẽ chuẩn bị khóa đúng biến thể và cấp tiền trước node")
        print("  " + subprocess.list2cmdline(command))
        return result

    imports = "import requests, flask, matplotlib, Crypto"
    imports += ", ecdsa" if algorithm == "ECDSA" else ""
    imports += ", oqs" if algorithm.startswith("ML-DSA") else ""
    preflight = subprocess.run(
        [args.python, "-c", imports], cwd=project,
        capture_output=True, text=True, check=False,
    )
    if preflight.returncode:
        detail = (preflight.stderr or preflight.stdout).strip()
        raise RuntimeError(f"Thiếu dependency cho {algorithm}: {detail}")

    occupied = [port for port in ports if not port_available(port)]
    if occupied:
        raise RuntimeError(
            f"Các cổng {occupied} đang được sử dụng; không thể khởi động "
            f"mạng {algorithm}."
        )

    wallet = None
    if algorithm in {"ML-DSA-65", "ML-DSA-87"}:
        wallet = provision_mldsa_wallets(project, algorithm)
        result["wallet_preparation"] = {
            key: value for key, value in wallet.items()
            if key != "sender_address"
        }
        print(f"[WALLET] {algorithm}: "
              f"{'đã tạo mới' if wallet['generated'] else 'tái sử dụng'} "
              f"ví {wallet['public_key_bytes']} byte; "
              f"số dư khởi tạo={wallet['balance']}", flush=True)

    processes = {}
    handles = []
    outputs = [] if pending_outputs is None else pending_outputs
    output_token = uuid.uuid4().hex
    try:
        node_log_dir = project / "logs"
        node_log_dir.mkdir(parents=True, exist_ok=True)
        for node in nodes:
            port = int(node["port"])
            node_log = node_log_dir / f"sec03_{run_id}_node_{port}.log"
            temporary = node_log.with_name(f"{node_log.name}.{output_token}.tmp")
            handle = temporary.open("x", encoding="utf-8")
            handles.append(handle)
            outputs.append((temporary, node_log))
            result["node_logs"][str(port)] = str(node_log)
            node_command = [
                args.python, "blockchain/blockchain.py", "-p", str(port)
            ]
            if node.get("peers"):
                node_command.extend(["--peers", ",".join(node["peers"])])
            processes[port] = subprocess.Popen(
                node_command, cwd=project, stdout=handle,
                stderr=subprocess.STDOUT,
            )

        wait_ready(ports, processes, args.startup_timeout)
        if wallet is not None:
            result["verified_balances"] = wait_funded(
                ports, wallet["sender_address"], args.startup_timeout
            )
            print(f"[FUNDING] {algorithm}: ví đúng khóa và >=22 coin "
                  f"trên {len(ports)}/{len(ports)} node", flush=True)
        print(f"\n[RUN] {algorithm}: mạng {len(ports)} node đã sẵn sàng; "
              "bắt đầu SEC-03", flush=True)
        completed = subprocess.run(command, cwd=project, check=False)
        result["exit_code"] = completed.returncode
        result["status"] = ("passed" if completed.returncode == 0
                            else "test_failed")
    finally:
        stop_nodes(processes)
        for handle in handles:
            handle.close()
    if pending_outputs is None and result["status"] == "passed":
        for temporary, path in outputs:
            os.replace(temporary, path)
    return result


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", action="append", choices=PROJECTS,
                        help="Chỉ chạy thuật toán này; có thể lặp lại.")
    parser.add_argument("--seed", type=int, default=3)
    parser.add_argument("--python", default=sys.executable,
                        help="Python có các gói trong requirements.txt.")
    parser.add_argument("--startup-timeout", type=float, default=30.0)
    parser.add_argument("--confirm-timeout", type=float, default=120.0)
    parser.add_argument("--settle", type=float, default=0.2)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--keep-raw-logs", action="store_true",
                        help="Giữ JSONL chi tiết sau khi lưu kết quả.")
    parser.add_argument("--dry-run", action="store_true",
                        help="In lệnh chạy, không khởi động node.")
    args = parser.parse_args()
    if not all(math.isfinite(value) for value in (
        args.startup_timeout, args.confirm_timeout, args.settle, args.delay
    )):
        parser.error("Các khoảng thời gian phải là số hữu hạn")
    if (args.startup_timeout <= 0 or args.confirm_timeout <= 0
            or args.settle < 0 or args.delay < 0):
        parser.error("timeout phải > 0; settle/delay phải >= 0")
    if args.workers < 1:
        parser.error("--workers phải >= 1")
    return args


def is_local_path(path):
    try:
        # Resolve ancestors as well, including Windows junctions.
        return not path.is_symlink() and path.resolve() == path
    except (OSError, RuntimeError) as exc:
        print(f"[CLEANUP] {path}: {exc}", file=sys.stderr)
        return False


def remove_output(path):
    try:
        if is_local_path(path) and path.is_file():
            path.unlink()
            return 1
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"[CLEANUP] {path}: {exc}", file=sys.stderr)
    return 0


def clean_bytecode_caches(selected):
    caches = [ROOT / "__pycache__"]
    for algorithm in selected:
        project = ROOT / PROJECTS[algorithm]
        caches.append(project / "__pycache__")
        for directory in ("blockchain", "blockchain_client", "benchmarks", "logs"):
            source = project / directory
            try:
                if source.is_dir() and is_local_path(source):
                    caches.extend(source.rglob("__pycache__"))
            except (OSError, RuntimeError) as exc:
                print(f"[CLEANUP] {source}: {exc}", file=sys.stderr)

    for cache in caches:
        try:
            if cache.is_dir() and is_local_path(cache):
                for path in cache.glob("*.pyc"):
                    remove_output(path)
                if not any(cache.iterdir()):
                    cache.rmdir()
        except FileNotFoundError:
            pass
        except (OSError, RuntimeError) as exc:
            print(f"[CLEANUP] {cache}: {exc}", file=sys.stderr)


def run_batch(args, selected):
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") \
        + "_" + uuid.uuid4().hex[:6]
    runs = []
    paths = {}
    pending_outputs = []
    for algorithm in selected:
        try:
            result = run_project(algorithm, PROJECTS[algorithm], args, run_id,
                                 pending_outputs=pending_outputs)
        except Exception as exc:
            result = {"algorithm": algorithm, "status": "startup_failed",
                      "error": str(exc), "exit_code": None}
            print(f"[ERROR] {algorithm}: {exc}", file=sys.stderr, flush=True)
        runs.append(result)
        log = result.get("log")
        if log and Path(log).is_file():
            paths[algorithm] = Path(log)

    if args.dry_run:
        return 0
    benchmark = analyze_logs(paths)
    for run in runs:
        path = paths.get(run["algorithm"])
        if path is not None:
            run["log_mtime_ns"] = path.stat().st_mtime_ns

    batch_path = ROOT / f"sec03_batch_{run_id}.json"
    temporary = batch_path.with_name(f"{batch_path.name}.{uuid.uuid4().hex}.tmp")
    report = {"runs": runs, "benchmark": benchmark}
    temporary.write_text(json.dumps(report, ensure_ascii=False,
                                    indent=2) + "\n", encoding="utf-8")
    reports_ready = report_batch(batch_path, pending_outputs=pending_outputs,
                                 source_path=temporary)
    passed = all(run.get("status") == "passed" for run in runs)
    if not passed or not reports_ready:
        return 1
    pending_outputs.append((temporary, batch_path))
    for staged, path in pending_outputs:
        os.replace(staged, path)

    if not args.keep_raw_logs:
        for run in runs:
            algorithm = run["algorithm"]
            path = paths.get(algorithm)
            if (run.get("status") == "passed" and algorithm in benchmark
                    and path is not None and path.with_suffix(".summary.json").is_file()):
                try:
                    path.unlink(missing_ok=True)
                except OSError as exc:
                    print(f"[CLEANUP] {path}: {exc}", file=sys.stderr)
    return 0


def main():
    args = parse_args()
    selected = list(dict.fromkeys(args.project or PROJECTS.keys()))
    prepare_runtime(ROOT, [PROJECTS[algorithm] for algorithm in selected])
    if not args.dry_run:
        clean_bytecode_caches(PROJECTS)
    try:
        return run_batch(args, selected)
    finally:
        if not args.dry_run:
            clean_bytecode_caches(selected)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[RESULT] Đã dừng; các node do script tạo được tắt.",
              file=sys.stderr)
        sys.exit(130)
