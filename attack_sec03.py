#!/usr/bin/env python3
"""
SEC-03 fuzzing: 1,000 POST attempts.

    python3 attack_sec03.py
    python3 attack_sec03.py --project-root /path/to/project --wallet Alice

Requires requests and the project's own Flask/cryptographic dependencies.

Replay uses the requested classification override: after an accepted baseline,
every replay that receives an HTTP response is counted as blocked. These replay
results are ASSUMED from project design, not verified from HTTP or ledger state.
Transport failures remain unknown; a failed baseline prevents a PASS result.

334 bit-flipping + 333 payload mutation + 1 baseline + 332 replay.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import math
import random
import re
import sys
import time
import uuid

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    raise SystemExit("Install requests: python3 -m pip install requests")


BIT = "Bit-flipping"
MUTATION = "Payload mutation"
REPLAY = "Replay"
PORTS = tuple(range(5000, 5006))


def hex_bytes(value: Any, label: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) % 2
        or re.fullmatch(r"[0-9a-fA-F]+", value) is None
    ):
        raise ValueError(f"{label}: invalid hex string")
    return bytes.fromhex(value)


def serialize(tx: dict[str, Any]) -> bytes:
    return json.dumps(
        tx, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


class ProjectClient:
    """Use the current project's wallet and signing endpoints locally."""

    def __init__(self, root: Path, client_file: Path | None):
        self.root = root
        candidates = (
            [client_file.resolve()]
            if client_file
            else [
                root / "blockchain_client" / "blockchain_client.py",
                root / "blockchain_client.py",
            ]
        )
        source = next((p for p in candidates if p.is_file()), None)
        if source is None:
            raise RuntimeError("Cannot find blockchain_client.py")

        sys.path.insert(0, str(root))
        sys.path.insert(0, str(source.parent))

        spec = importlib.util.spec_from_file_location("sec03_client", source)
        if spec is None or spec.loader is None:
            raise RuntimeError("Cannot load project client")

        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        app = getattr(module, "app", None)
        if not callable(getattr(app, "test_client", None)):
            raise RuntimeError("Project client must expose Flask app")

        self.client = app.test_client()
        self.algorithm = str(getattr(module, "SIG_ALG", "project-defined"))

    def new_wallet(self) -> dict[str, Any]:
        response = self.client.get("/wallet/new")
        wallet = response.get_json(silent=True)
        if response.status_code != 200 or not isinstance(wallet, dict):
            raise RuntimeError("Local /wallet/new failed")
        hex_bytes(wallet.get("public_key"), "public_key")
        hex_bytes(wallet.get("private_key"), "private_key")
        return wallet

    def sample_wallets(self) -> dict[str, dict[str, Any]]:
        for path in (
            self.root / "configs" / "wallets.json",
            self.root / "wallets.json",
        ):
            if path.is_file():
                with path.open(encoding="utf-8") as handle:
                    data = json.load(handle)
                if not isinstance(data, dict):
                    raise ValueError("wallets.json must contain an object")
                return {
                    str(name): wallet
                    for name, wallet in data.items()
                    if isinstance(wallet, dict)
                }
        return {}

    def sign(
        self, wallet: dict[str, Any], recipient: str, amount: int
    ) -> dict[str, Any]:
        nonce = str(uuid.uuid4())
        response = self.client.post(
            "/generate/transaction",
            data={
                "sender_address": wallet["public_key"],
                "sender_private_key": wallet["private_key"],
                "recipient_address": recipient,
                "amount": str(amount),
                "nonce": nonce,
            },
        )
        data = response.get_json(silent=True)
        if response.status_code != 200 or not isinstance(data, dict):
            raise RuntimeError("Project signing endpoint failed")

        original = data.get("transaction")
        if not isinstance(original, dict):
            raise RuntimeError("Signing response has no transaction object")

        tx = copy.deepcopy(original)
        tx.pop("sender_private_key", None)
        tx.pop("private_key", None)

        signature = data.get("signature", tx.get("signature"))
        hex_bytes(signature, "signature")

        if tx.get("sender_address") != wallet["public_key"]:
            raise RuntimeError("Signer returned an unexpected sender")
        if tx.get("recipient_address") != recipient:
            raise RuntimeError("Signer returned an unexpected recipient")
        if str(tx.get("amount", tx.get("value"))) != str(amount):
            raise RuntimeError("Signer returned an unexpected amount")

        # Matches the supplied API: amount becomes string value for verification.
        tx.pop("value", None)
        tx["amount"] = amount
        tx["signature"] = signature
        tx.setdefault("nonce", nonce)
        serialize(tx)
        return tx

    def fixtures(self, requested_wallet: str | None) -> list[dict[str, Any]]:
        recipient = self.new_wallet()["public_key"]
        key_size = len(hex_bytes(recipient, "recipient"))
        wallets = self.sample_wallets()

        if requested_wallet and requested_wallet not in wallets:
            raise RuntimeError(f"Wallet {requested_wallet!r} not found")

        sender = None
        baseline = None
        sender_name = None
        names = [requested_wallet] if requested_wallet else list(wallets)

        for name in names:
            wallet = wallets[name]
            try:
                balance = float(wallet.get("initial_balance", 0))
                if not math.isfinite(balance) or balance < 1:
                    continue
                if len(hex_bytes(wallet.get("public_key"), "public_key")) != key_size:
                    continue
                hex_bytes(wallet.get("private_key"), "private_key")
                candidate = self.sign(wallet, recipient, 1)
            except (ValueError, TypeError, KeyError, RuntimeError):
                continue

            sender, baseline, sender_name = wallet, candidate, name
            break

        if sender is None:
            if requested_wallet:
                raise RuntimeError(
                    "Selected wallet cannot sign or has configured balance below 1"
                )
            sender = self.new_wallet()
            baseline = self.sign(sender, recipient, 1)
            sender_name = "generated-wallet"
            print("WARNING: New sender has no guaranteed balance.")

        print(f"Algorithm: {self.algorithm}; sender: {sender_name}")
        print("Generating 668 signed fixtures...")

        # Distinct signed amounts also support deterministic RSA signatures.
        fixtures = [
            self.sign(sender, recipient, amount)
            for amount in range(2, 669)
        ]
        fixtures.append(baseline)

        if len(fixtures) != 668:
            raise RuntimeError("Unexpected fixture count")

        if "ML-DSA-44" in self.algorithm.upper():
            if key_size != 1312 or any(
                len(hex_bytes(tx["signature"], "signature")) != 2420
                for tx in fixtures
            ):
                raise RuntimeError("Unexpected ML-DSA-44 key/signature size")

        return fixtures


def flip_bits(tx: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    result = copy.deepcopy(tx)
    signature = bytearray(hex_bytes(tx["signature"], "signature"))
    for bit in rng.sample(range(len(signature) * 8), rng.randint(1, 4)):
        signature[bit // 8] ^= 1 << (bit % 8)
    result["signature"] = signature.hex()
    return result


def mutate(
    tx: dict[str, Any], rng: random.Random, change_amount: bool
) -> dict[str, Any]:
    result = copy.deepcopy(tx)
    if change_amount:
        result["amount"] *= 100
    else:
        address = list(result["recipient_address"])
        index = rng.randrange(len(address))
        address[index] = format(int(address[index], 16) ^ 1, "x")
        result["recipient_address"] = "".join(address)
    assert result["signature"] == tx["signature"]
    return result


@dataclass
class Observation:
    status: int | None
    body: Any
    error: str | None
    elapsed_ms: float


@dataclass
class Stats:
    requests: int = 0
    blocked: int = 0
    accepted: int = 0
    unknown: int = 0
    baseline_ok: int = 0
    baseline_failed: int = 0
    assumed_blocked: int = 0


def post(
    session: requests.Session, port: int, wire: bytes, timeout: float
) -> Observation:
    started = time.monotonic()
    try:
        response = session.post(
            f"http://127.0.0.1:{port}/transactions/new",
            data=wire,
            headers={"Content-Type": "application/json"},
            timeout=(timeout, timeout),
            allow_redirects=False,
        )
        try:
            body = response.json()
        except ValueError:
            body = {"non_json_response": response.text[:2000]}
        return Observation(
            response.status_code,
            body,
            None,
            round((time.monotonic() - started) * 1000, 3),
        )
    except requests.RequestException as exc:
        return Observation(
            None,
            None,
            f"{type(exc).__name__}: {exc}",
            round((time.monotonic() - started) * 1000, 3),
        )


def api_accepted(observation: Observation) -> bool:
    if observation.status not in {200, 201}:
        return False
    body = observation.body
    if not isinstance(body, dict) or "non_json_response" in body:
        return False
    if (
        body.get("success") is False
        or body.get("accepted") is False
        or bool(body.get("error"))
        or str(body.get("status", "")).lower()
        in {"failed", "error", "rejected", "invalid"}
    ):
        return False
    return True


def classify(
    kind: str, observation: Observation, baseline_ok: bool
) -> tuple[str, str, str]:
    """
    Returns result, reason, evidence_type.

    Baselines are handled separately and never enter this function.
    """
    if observation.status is None:
        return "unknown", "network_error_or_timeout", "transport"

    if kind == REPLAY:
        if not baseline_ok:
            return "unknown", "baseline_not_established", "baseline"

        # Requested override: any received HTTP response counts as blocked.
        # Preserve its assumed nature in both logs and the terminal report.
        return (
            "blocked",
            "replay_override_assumes_silent_deduplication",
            "assumption",
        )

    if observation.status == 406:
        return "blocked", "http_406_rejection", "http_response"

    if api_accepted(observation):
        return "accepted", "api_accepted_mutated_transaction", "http_response"

    return "unknown", "unexpected_response", "http_response"


def print_results(stats: dict[str, Stats]) -> int:
    total = Stats()
    rows = []
    fields = tuple(Stats.__dataclass_fields__)

    for name, item in stats.items():
        attacks = item.requests - item.baseline_ok - item.baseline_failed
        rate = f"{100 * item.accepted / attacks:.2f}%" if attacks else "N/A"
        rows.append([
            name, str(item.requests), str(item.blocked), str(item.accepted),
            str(item.unknown),
            f"{item.baseline_ok}/{item.baseline_failed}", rate,
        ])
        for field in fields:
            setattr(total, field, getattr(total, field) + getattr(item, field))

    attacks = total.requests - total.baseline_ok - total.baseline_failed
    rows.append([
        "TOTAL", str(total.requests), str(total.blocked), str(total.accepted),
        str(total.unknown),
        f"{total.baseline_ok}/{total.baseline_failed}",
        f"{100 * total.accepted / attacks:.2f}%" if attacks else "N/A",
    ])

    headers = [
        "Scenario", "Requests", "Blocked", "API accepted",
        "Unknown", "Baseline OK/Fail", "API accept %",
    ]
    widths = [
        max(len(row[i]) for row in [headers, *rows])
        for i in range(len(headers))
    ]
    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    print("\nSEC-03 RESULTS")
    print("MODE: Replay classification override (assumed silent deduplication)")
    print(border)
    for index, row in enumerate([headers, *rows]):
        print("| " + " | ".join(
            value.ljust(width) for value, width in zip(row, widths)
        ) + " |")
        if index == 0:
            print(border)
    print(border)
    print(
        f"Blocked includes {total.assumed_blocked} assumed replay results; "
        "ledger state was not verified."
    )

    passed = (
        total.requests == 1000
        and total.blocked == 999
        and total.accepted == 0
        and total.unknown == 0
        and total.baseline_ok == 1
        and total.baseline_failed == 0
    )

    if passed:
        print("PASS applies to the configured override classification.")
        print("PASS: 999/999 attack attempts blocked (100%); baseline accepted.")
        return 0

    print("NOT PASS: Baseline, transport, or mutation results require review.")
    return 1 if total.accepted else 2


def run(args: argparse.Namespace) -> int:
    root = args.project_root.resolve()
    fixtures = ProjectClient(root, args.client_file).fixtures(args.wallet)

    if args.save_fixtures:
        path = root / "signed_transactions.json"
        with path.open("x", encoding="utf-8") as handle:
            json.dump(
                fixtures, handle, ensure_ascii=False, indent=2, allow_nan=False
            )
            handle.write("\n")
        print(f"Fixtures: {path}")

    rng = random.Random(args.seed)
    cases = [
        (BIT, serialize(flip_bits(tx, rng)), False)
        for tx in fixtures[:334]
    ]
    cases.extend(
        (MUTATION, serialize(mutate(tx, rng, index % 2 == 0)), False)
        for index, tx in enumerate(fixtures[334:667])
    )
    rng.shuffle(cases)

    # Every replay uses exactly the same bytes, including nonce/signature.
    replay_wire = serialize(fixtures[-1])
    cases.append((REPLAY, replay_wire, True))
    cases.extend((REPLAY, replay_wire, False) for _ in range(332))
    assert len(cases) == 1000

    stats = {kind: Stats() for kind in (BIT, MUTATION, REPLAY)}
    replay_ports = list(PORTS)
    rng.shuffle(replay_ports)
    replay_index = 0
    baseline_ok = False
    interrupted = False

    log_path = args.log.resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.trust_env = False
    session.mount("http://", HTTPAdapter(max_retries=0))

    try:
        with log_path.open("x", encoding="utf-8") as log:
            print(f"Detailed log: {log_path}")
            for number, (kind, wire, is_baseline) in enumerate(cases, 1):
                if kind == REPLAY:
                    port = replay_ports[replay_index % len(replay_ports)]
                    replay_index += 1
                else:
                    port = rng.choice(PORTS)

                observation = post(session, port, wire, args.timeout)
                item = stats[kind]
                item.requests += 1

                if is_baseline:
                    baseline_ok = api_accepted(observation)
                    result = "baseline_ok" if baseline_ok else "baseline_failed"
                    reason = result
                    evidence_type = "http_response"
                else:
                    result, reason, evidence_type = classify(
                        kind, observation, baseline_ok
                    )

                setattr(item, result, getattr(item, result) + 1)
                if result == "blocked" and evidence_type == "assumption":
                    item.assumed_blocked += 1

                record = {
                    "time_utc": datetime.now(timezone.utc).isoformat(),
                    "request": number,
                    "scenario": kind,
                    "port": port,
                    "baseline": is_baseline,
                    "result": result,
                    "reason": reason,
                    "evidence_type": evidence_type,
                    "ledger_verified": False,
                    "http_status": observation.status,
                    "elapsed_ms": observation.elapsed_ms,
                    "response": observation.body,
                    "network_error": observation.error,
                }
                log.write(json.dumps(record, ensure_ascii=False) + "\n")
                log.flush()

                if number % 100 == 0:
                    print(f"Completed {number}/1000 POST attempts")

                if is_baseline:
                    print(f"Replay baseline: {result}")
                    if args.settle:
                        time.sleep(args.settle)

                if number < len(cases) and args.delay:
                    time.sleep(args.delay)

    except KeyboardInterrupt:
        interrupted = True
        print("\nInterrupted; reporting partial results.")
    finally:
        session.close()

    result = print_results(stats)
    print(f"Detailed JSONL log: {log_path}")
    return 130 if interrupted else result


def parse_args() -> argparse.Namespace:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--client-file", type=Path)
    parser.add_argument("--wallet")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--settle", type=float, default=2.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=3)
    parser.add_argument("--save-fixtures", action="store_true")
    parser.add_argument(
        "--log", type=Path,
        default=Path(f"sec03_{stamp}_{uuid.uuid4().hex[:8]}.jsonl"),
    )
    args = parser.parse_args()

    for name in ("timeout", "settle", "delay"):
        if not math.isfinite(getattr(args, name)):
            parser.error(f"--{name} must be finite")
    if args.timeout <= 0 or args.settle < 0 or args.delay < 0:
        parser.error("timeout must be > 0; settle/delay must be >= 0")
    return args


def main() -> int:
    args = parse_args()
    try:
        return run(args)
    except KeyboardInterrupt:
        return 130
    except FileExistsError as exc:
        print(
            f"Output already exists: {exc.filename}. Choose another output path.",
            file=sys.stderr,
        )
        return 2
    except Exception as exc:
        print(f"SEC-03 error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
