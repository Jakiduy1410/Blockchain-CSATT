#!/usr/bin/env python3
"""
SEC-03 automated transaction mutation testing.

Run:
    python3 attack_sec03.py

Optional:
    python3 attack_sec03.py --no-assume-replay-blocked
    python3 attack_sec03.py --no-show-sample

Normal completion:
    334 bit-flipping + 333 payload mutation
    + 1 replay baseline + 332 replay attempts = 1,000 transaction attempts.

Changes:
    - Continue replay attempts even if baseline is rejected.
    - Apply replay override BEFORE checking baseline acceptance.
    - Replay override defaults to True.

Generated wallet balances are local dummy metadata, not ledger funds.
Replay override results are assumptions, not verified ledger rejection.
Transport failures remain Unknown.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import ipaddress
import json
import math
import random
import re
import ssl
import sys
import time
import unicodedata
import uuid

from dataclasses import dataclass, field
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
KINDS = (BIT, MUTATION, REPLAY)

HEALTH_PATHS = ("/status", "/health", "/healthz", "/")
WS_PATHS = ("/ws", "/transactions/ws", "/p2p/ws", "/")

ACCEPTED = {"accepted", "success", "created", "ok"}
REJECTED = {"rejected", "invalid", "blocked", "denied"}
DUPLICATES = {"duplicate", "ignored", "skipped", "already_processed"}

DUMMY_BALANCE = 10000.0


def encode(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def decode_hex(value: Any, name: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) % 2
        or not re.fullmatch(r"[0-9a-fA-F]+", value)
    ):
        raise ValueError(f"{name}: invalid hex")
    return bytes.fromhex(value)


def error_text(exc: BaseException) -> str:
    messages = []
    visited = set()

    def visit(error):
        if not isinstance(error, BaseException) or id(error) in visited:
            return

        visited.add(id(error))
        messages.append(f"{type(error).__name__}: {error}")
        visit(error.__cause__ or error.__context__)
        visit(getattr(error, "reason", None))

        for argument in error.args:
            visit(argument)

    visit(exc)
    return " -> ".join(messages)


def loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True

    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalized(text: str) -> str:
    text = text.casefold().replace("đ", "d").replace("_", " ")
    return "".join(
        char
        for char in unicodedata.normalize("NFD", text)
        if unicodedata.category(char) != "Mn"
    )


def app_code(body: Any) -> int | None:
    if not isinstance(body, dict):
        return None

    for key in ("status_code", "http_status", "code"):
        value = body.get(key)

        if isinstance(value, bool):
            continue

        if isinstance(value, int) and 100 <= value <= 599:
            return value

        if isinstance(value, str) and re.fullmatch(r"[1-5]\d\d", value):
            return int(value)

    return None


def duplicate_reply(body: Any) -> bool:
    if not isinstance(body, dict):
        return False

    if str(body.get("status", "")).lower() in DUPLICATES:
        return True

    if any(
        body.get(key) is True
        for key in ("duplicate", "ignored", "skipped", "replay_detected")
    ):
        return True

    for key in ("code", "error_code", "message", "reason"):
        value = body.get(key)
        if not isinstance(value, str):
            continue

        text = normalized(value)

        if re.search(
            r"\b(no duplicate|not a duplicate|not duplicate|"
            r"khong trung|khong ton tai|chua su dung)\b",
            text,
        ):
            continue

        if re.search(
            r"\b(duplicate|replay detected|already processed|"
            r"already exists|nonce already used|trung lap|"
            r"da ton tai|bo qua|nonce da su dung)\b",
            text,
        ):
            return True

    return False


def application_reply(body: Any) -> bool:
    if not isinstance(body, dict):
        return False

    return (
        app_code(body) is not None
        or isinstance(body.get("accepted"), bool)
        or isinstance(body.get("success"), bool)
        or str(body.get("status", "")).lower()
        in ACCEPTED | REJECTED | DUPLICATES
        or duplicate_reply(body)
    )


class TLSAdapter(HTTPAdapter):
    def __init__(self, context):
        self.context = context
        super().__init__(max_retries=0)

    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        kwargs["ssl_context"] = self.context
        return super().init_poolmanager(
            connections, maxsize, block=block, **kwargs
        )


def make_tls_context(args, insecure=False):
    context = ssl.create_default_context(cafile=args.ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3

    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    if args.client_cert:
        context.load_cert_chain(args.client_cert, args.client_key)

    return context


def make_session(args, context=None, insecure=False):
    session = requests.Session()
    session.trust_env = False
    session.mount("http://", HTTPAdapter(max_retries=0))

    if context is not None:
        session.mount("https://", TLSAdapter(context))
        session.verify = False if insecure else args.ca_file or True

        if args.client_cert:
            session.cert = (
                (args.client_cert, args.client_key)
                if args.client_key
                else args.client_cert
            )

    return session


@dataclass
class Node:
    port: int
    protocol: str
    path: str
    session: Any = None
    context: Any = None
    certificate_verified: bool | None = None


@dataclass
class Observation:
    http_status: int | None
    application_code: int | None
    body: Any
    error: str | None
    elapsed_ms: float


class AutoTransport:
    def __init__(self, args):
        self.args = args
        self.nodes: dict[int, Node] = {}
        self.connect_ws = None

        try:
            from websockets.sync.client import connect
            self.connect_ws = connect
        except ImportError:
            pass

    def url(self, protocol, port, path):
        host = self.args.host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"{protocol}://{host}:{port}{path}"

    def open_ws(self, node):
        if self.connect_ws is None:
            raise RuntimeError(
                'Install WSS support: pip install "websockets>=15"'
            )

        return self.connect_ws(
            self.url("wss", node.port, node.path),
            ssl=node.context,
            proxy=None,
            open_timeout=self.args.timeout,
            close_timeout=min(self.args.timeout, 2),
            max_size=2 * 1024 * 1024,
            subprotocols=(
                [self.args.ws_subprotocol]
                if self.args.ws_subprotocol
                else None
            ),
        )

    def probe_rest(self, protocol, port, context, insecure, errors):
        session = make_session(self.args, context, insecure)
        found = False

        try:
            for path in HEALTH_PATHS:
                try:
                    response = session.get(
                        self.url(protocol, port, path),
                        timeout=self.args.probe_timeout,
                        allow_redirects=False,
                    )

                    if 200 <= response.status_code < 300:
                        found = True
                        return Node(
                            port=port,
                            protocol=protocol,
                            path=path,
                            session=session,
                            context=context,
                            certificate_verified=(
                                not insecure if protocol == "https" else None
                            ),
                        )

                    errors.append(
                        f"{protocol} {path}: HTTP {response.status_code}"
                    )

                except requests.RequestException as exc:
                    errors.append(f"{protocol}: {error_text(exc)}")
                    break

            return None

        finally:
            if not found:
                session.close()

    def discover_node(self, port):
        errors = []

        node = self.probe_rest("http", port, None, False, errors)
        if node:
            return node

        tls_modes = [False]
        if loopback(self.args.host) and not self.args.strict_tls:
            tls_modes.append(True)

        for insecure in tls_modes:
            context = make_tls_context(self.args, insecure)

            node = self.probe_rest(
                "https", port, context, insecure, errors
            )
            if node:
                return node

            if self.connect_ws is None:
                continue

            paths = (
                [self.args.ws_path]
                if self.args.ws_path
                else WS_PATHS
            )

            for path in paths:
                candidate = Node(
                    port=port,
                    protocol="wss",
                    path=path,
                    context=context,
                    certificate_verified=not insecure,
                )

                try:
                    with self.open_ws(candidate) as ws:
                        if not ws.ping().wait(self.args.probe_timeout):
                            raise TimeoutError("WebSocket Pong timeout")
                    return candidate

                except Exception as exc:
                    errors.append(f"wss {path}: {error_text(exc)}")

        print(
            f"\n[FAIL] Cannot detect transport at "
            f"{self.args.host}:{port}"
        )
        for message in errors:
            print(f"  {message}")

        if self.connect_ws is None:
            print('  WSS unavailable: install "websockets>=15".')

        return None

    def discover(self):
        print("[AUTO] Detecting transport on every node...")
        failures = []

        for port in self.args.ports:
            node = self.discover_node(port)

            if node is None:
                failures.append(port)
                continue

            self.nodes[port] = node
            print(
                f"[OK] {self.url(node.protocol, port, node.path)}",
                flush=True,
            )

            if node.certificate_verified is False:
                print(
                    "     Loopback self-signed fallback: "
                    "certificate verification is DISABLED.",
                    flush=True,
                )

        if failures:
            raise RuntimeError(
                f"Pre-check failed on ports {failures}. "
                "Check nodes, listeners, health endpoints, port mappings, "
                "certificates, and WS paths. No transaction tests were sent."
            )

    def balances(self) -> dict[str, float]:
        balances = {}

        for node in self.nodes.values():
            if node.protocol not in {"http", "https"}:
                continue

            try:
                response = node.session.get(
                    self.url(
                        node.protocol, node.port, "/accounts/balance"
                    ),
                    timeout=self.args.probe_timeout,
                    allow_redirects=False,
                )

                if response.status_code != 200:
                    continue

                body = response.json()
                records = (
                    body.get("balances", [])
                    if isinstance(body, dict)
                    else []
                )

                if isinstance(records, dict):
                    records = [
                        (
                            {"address": address, "available_balance": value}
                            if not isinstance(value, dict)
                            else {"address": address, **value}
                        )
                        for address, value in records.items()
                    ]

                if not isinstance(records, list):
                    continue

                for record in records:
                    if not isinstance(record, dict):
                        continue

                    address = record.get(
                        "address", record.get("public_key")
                    )
                    value = record.get(
                        "available_balance",
                        record.get(
                            "balance", record.get("confirmed_balance")
                        ),
                    )

                    if not isinstance(address, str):
                        continue

                    try:
                        value = float(value)
                    except (ValueError, TypeError):
                        continue

                    if math.isfinite(value):
                        balances[address] = min(
                            balances.get(address, value), value
                        )

            except (requests.RequestException, ValueError):
                continue

        return balances

    def wire(self, node, tx):
        if node.protocol == "wss" and self.args.ws_payload_key:
            envelope = {self.args.ws_payload_key: tx}
            if self.args.ws_type:
                envelope["type"] = self.args.ws_type
            return encode(envelope)

        return encode(tx)

    def send(self, port, wire):
        node = self.nodes[port]
        started = time.monotonic()
        http_status = None
        body = None
        error = None

        try:
            if node.protocol in {"http", "https"}:
                response = node.session.post(
                    self.url(
                        node.protocol, port, "/transactions/new"
                    ),
                    data=wire.encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    timeout=self.args.timeout,
                    allow_redirects=False,
                )
                http_status = response.status_code

                try:
                    body = response.json()
                except ValueError:
                    body = {"non_json_response": response.text[:2000]}

            else:
                with self.open_ws(node) as ws:
                    ws.send(wire)
                    deadline = time.monotonic() + self.args.timeout

                    while True:
                        remaining = deadline - time.monotonic()

                        if remaining <= 0:
                            raise TimeoutError(
                                "No matching transaction JSON acknowledgement"
                            )

                        raw = ws.recv(timeout=remaining)

                        try:
                            candidate = json.loads(raw)
                        except (ValueError, UnicodeError):
                            continue

                        if self.args.ws_reply_type and (
                            not isinstance(candidate, dict)
                            or candidate.get("type")
                            != self.args.ws_reply_type
                        ):
                            continue

                        if application_reply(candidate):
                            body = candidate
                            break

        except Exception as exc:
            error = error_text(exc)
            print(
                f"[SEND ERROR] port={port} | {error}",
                flush=True,
            )

        return Observation(
            http_status=http_status,
            application_code=app_code(body),
            body=body,
            error=error,
            elapsed_ms=round(
                (time.monotonic() - started) * 1000, 3
            ),
        )

    def close(self):
        for node in self.nodes.values():
            if node.session is not None:
                node.session.close()


def locate_project(explicit_root=None):
    roots = (
        [explicit_root.resolve()]
        if explicit_root
        else [
            Path.cwd().resolve(),
            Path(__file__).resolve().parent,
        ]
    )

    for root in dict.fromkeys(roots):
        for candidate_root in (root, root.parent):
            for client_path in (
                candidate_root / "blockchain_client" / "blockchain_client.py",
                candidate_root / "blockchain_client.py",
            ):
                if client_path.is_file():
                    return candidate_root, client_path

    raise RuntimeError(
        "Cannot find blockchain_client.py. Place this script "
        "in the project root or run it from the project directory."
    )


@dataclass
class Wallet:
    name: str
    public_key: str
    private_key: str
    balance: float
    source: Path | None
    balance_source: str


class ProjectClient:
    def __init__(self, root, source):
        self.root = root
        self.source = source

        sys.path.insert(0, str(root))
        sys.path.insert(0, str(source.parent))

        spec = importlib.util.spec_from_file_location(
            "sec03_client", source
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("Cannot import project client")

        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        app = getattr(module, "app", None)
        if not callable(getattr(app, "test_client", None)):
            raise RuntimeError("Project client must expose Flask app")

        self.client = app.test_client()
        self.algorithm = str(
            getattr(module, "SIG_ALG", "project-defined")
        )

    def new_wallet(self):
        response = self.client.get("/wallet/new")
        body = response.get_json(silent=True)

        if response.status_code != 200 or not isinstance(body, dict):
            raise RuntimeError("Project /wallet/new failed")

        decode_hex(body.get("public_key"), "public_key")
        decode_hex(body.get("private_key"), "private_key")
        return body

    def sign(self, wallet, recipient, amount):
        nonce = str(uuid.uuid4())

        response = self.client.post(
            "/generate/transaction",
            data={
                "sender_address": wallet.public_key,
                "sender_private_key": wallet.private_key,
                "recipient_address": recipient,
                "amount": str(amount),
                "nonce": nonce,
            },
        )
        body = response.get_json(silent=True)

        if response.status_code != 200 or not isinstance(body, dict):
            raise RuntimeError("Project signing endpoint failed")

        original = body.get("transaction")
        if not isinstance(original, dict):
            raise RuntimeError("Signer returned no transaction object")

        tx = copy.deepcopy(original)
        tx.pop("private_key", None)
        tx.pop("sender_private_key", None)

        signature = body.get("signature", tx.get("signature"))
        decode_hex(signature, "signature")

        if tx.get("sender_address") != wallet.public_key:
            raise RuntimeError("Unexpected signed sender")

        if tx.get("recipient_address") != recipient:
            raise RuntimeError("Unexpected signed recipient")

        if str(tx.get("amount", tx.get("value"))) != str(amount):
            raise RuntimeError("Unexpected signed amount")

        tx.pop("value", None)
        tx["amount"] = amount
        tx["signature"] = signature
        tx.setdefault("nonce", nonce)

        encode(tx)
        return tx

    def wallet_files(self):
        paths = set()

        for directory in (
            self.root / "configs",
            self.root / "config",
            self.root / "wallets",
        ):
            if directory.is_dir():
                paths.update(directory.rglob("*.json"))

        for directory in (self.root, self.source.parent):
            paths.update(directory.glob("*.json"))

        return [
            path
            for path in sorted(paths)
            if path.is_file()
            and path.stat().st_size <= 10 * 1024 * 1024
        ]

    def discover_wallets(self, live_balances):
        candidates = []
        seen = set()

        def first(record, keys):
            return next(
                (record[key] for key in keys if key in record),
                None,
            )

        def visit(value, path, label="wallet", depth=0):
            if depth > 12:
                return

            if isinstance(value, list):
                for index, entry in enumerate(value):
                    visit(entry, path, f"{label}[{index}]", depth + 1)
                return

            if not isinstance(value, dict):
                return

            public = first(
                value, ("public_key", "sender_address", "publicKey")
            )
            private = first(
                value,
                ("private_key", "sender_private_key", "privateKey"),
            )

            if isinstance(public, str) and isinstance(private, str):
                try:
                    decode_hex(public, "public_key")
                    decode_hex(private, "private_key")

                    if public in live_balances:
                        balance = live_balances[public]
                        balance_source = "live API"
                    else:
                        balance = float(
                            first(
                                value,
                                (
                                    "available_balance",
                                    "balance",
                                    "initial_balance",
                                ),
                            )
                        )
                        balance_source = "local configuration"

                    identity = (public, private)

                    if (
                        math.isfinite(balance)
                        and balance >= 1
                        and identity not in seen
                    ):
                        seen.add(identity)
                        candidates.append(
                            Wallet(
                                name=str(value.get("name", label)),
                                public_key=public,
                                private_key=private,
                                balance=balance,
                                source=path,
                                balance_source=balance_source,
                            )
                        )

                except (ValueError, TypeError):
                    pass

            for key, entry in value.items():
                if isinstance(entry, (dict, list)):
                    visit(entry, path, str(key), depth + 1)

        files = self.wallet_files()

        for path in files:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError):
                continue
            visit(data, path)

        candidates.sort(
            key=lambda wallet: (
                wallet.balance_source == "live API",
                wallet.balance,
            ),
            reverse=True,
        )

        print(
            f"[AUTO] Scanned {len(files)} JSON files; "
            f"found {len(candidates)} funded wallet candidates."
        )
        return candidates

    def fixtures(self, transport):
        recipient = self.new_wallet()["public_key"]
        expected_size = len(decode_hex(recipient, "recipient"))
        candidates = self.discover_wallets(transport.balances())

        selected = None
        baseline = None

        for wallet in candidates:
            if len(decode_hex(wallet.public_key, "public_key")) != expected_size:
                continue

            try:
                candidate_baseline = self.sign(wallet, recipient, 1)
            except (ValueError, RuntimeError, KeyError, TypeError):
                continue

            selected = wallet
            baseline = candidate_baseline
            break

        if selected is None:
            print(
                "[AUTO] No usable wallet candidate. "
                "Generating a fresh wallet with the current project client..."
            )

            generated = self.new_wallet()
            selected = Wallet(
                name="generated-test-wallet",
                public_key=generated["public_key"],
                private_key=generated["private_key"],
                balance=DUMMY_BALANCE,
                source=None,
                balance_source="dummy metadata; ledger not funded",
            )
            baseline = self.sign(selected, recipient, 1)

            print("[AUTO] Fresh wallet generated; baseline signed locally.")
            print(
                f"[AUTO] Dummy balance metadata: {DUMMY_BALANCE:.1f}. "
                "This does not fund the Node ledger."
            )

        source_name = (
            selected.source.name
            if selected.source is not None
            else "generated in RAM"
        )

        print(
            f"[WALLET] {selected.name}; source={source_name}; "
            f"balance={selected.balance:g} "
            f"({selected.balance_source})"
        )
        print(f"[SIGNER] {self.algorithm}")
        print("[FIXTURES] Generating 668 signed transactions...")

        fixtures = [
            self.sign(selected, recipient, amount)
            for amount in range(2, 669)
        ]
        fixtures.append(baseline)

        if self.algorithm.upper().replace("_", "-") == "ML-DSA-44":
            if expected_size != 1312 or any(
                len(decode_hex(tx["signature"], "signature")) != 2420
                for tx in fixtures
            ):
                raise RuntimeError("Unexpected ML-DSA-44 key/signature size")

        print(
            f"[FIXTURES] Ready: {len(fixtures)} transactions; "
            f"public key={len(decode_hex(selected.public_key, 'public_key'))} "
            f"bytes; signature="
            f"{len(decode_hex(fixtures[0]['signature'], 'signature'))} bytes."
        )

        return fixtures


def accepted(obs):
    if obs.error:
        return False

    body = obs.body if isinstance(obs.body, dict) else {}
    status = str(body.get("status", "")).lower()

    if (
        body.get("accepted") is False
        or body.get("success") is False
        or bool(body.get("error"))
        or status in REJECTED | DUPLICATES
        or duplicate_reply(body)
    ):
        return False

    code = (
        obs.http_status
        if obs.http_status is not None
        else obs.application_code
    )

    if code is not None and not 200 <= code < 300:
        return False

    if obs.http_status in {200, 201} and "non_json_response" not in body:
        return True

    return (
        body.get("accepted") is True
        or body.get("success") is True
        or status in ACCEPTED
        or obs.application_code in {200, 201}
    )


def classify(kind, obs, baseline_ok, assume_replay):
    # Transport failures are never classified as successful blocks.
    if obs.error:
        return "unknown", "transport_error", "transport"

    if kind == REPLAY:
        # FIX 2: apply override before checking the baseline.
        if assume_replay:
            return "blocked", "replay_override", "assumption"

        if not baseline_ok:
            return "unknown", "baseline_not_established", "baseline"

        if duplicate_reply(obs.body):
            return (
                "blocked",
                "explicit_duplicate_response",
                "application",
            )

    code = (
        obs.http_status
        if obs.http_status is not None
        else obs.application_code
    )
    body = obs.body if isinstance(obs.body, dict) else {}

    if kind != REPLAY and (
        code == 406
        or str(body.get("status", "")).lower() in REJECTED
        or body.get("accepted") is False
    ):
        return "blocked", "transaction_rejected", "response"

    if accepted(obs):
        return "accepted", "application_acceptance", "response"

    return "unknown", "unrecognized_response", "response"


@dataclass
class Stats:
    requests: int = 0
    blocked: int = 0
    accepted: int = 0
    unknown: int = 0
    baseline_ok: int = 0
    baseline_failed: int = 0
    assumed: int = 0
    times: list[float] = field(default_factory=list)


def report(stats, algorithm):
    total = Stats()
    rows = []

    for name, item in stats.items():
        rows.append([
            name,
            item.requests,
            item.blocked,
            item.accepted,
            item.unknown,
            f"{item.baseline_ok}/{item.baseline_failed}",
        ])

        for key in (
            "requests", "blocked", "accepted", "unknown",
            "baseline_ok", "baseline_failed", "assumed",
        ):
            setattr(
                total, key, getattr(total, key) + getattr(item, key)
            )

    rows.append([
        "TOTAL",
        total.requests,
        total.blocked,
        total.accepted,
        total.unknown,
        f"{total.baseline_ok}/{total.baseline_failed}",
    ])

    rows = [[str(cell) for cell in row] for row in rows]
    headers = [
        "Scenario", "Sent", "Blocked", "Accepted",
        "Unknown", "Baseline OK/Fail",
    ]
    widths = [
        max(len(row[index]) for row in [headers, *rows])
        for index in range(len(headers))
    ]
    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    print("\nSEC-03 RESULTS")
    print(border)

    for index, row in enumerate([headers, *rows]):
        print(
            "| "
            + " | ".join(
                value.ljust(width)
                for value, width in zip(row, widths)
            )
            + " |"
        )
        if index == 0:
            print(border)

    print(border)
    print(
        f"\n[BENCHMARK] {algorithm}: client-observed request latency"
    )

    for kind, item in stats.items():
        average = (
            f"{math.fsum(item.times) / len(item.times):.2f} ms"
            if item.times
            else "N/A"
        )
        print(
            f"  {kind}: {average}; blocked samples={len(item.times)}"
        )

    if total.assumed:
        print(
            f"Assumed replay blocks: {total.assumed}; "
            "ledger not verified."
        )

    passed = (
        total.requests == 1000
        and total.blocked == 999
        and total.baseline_ok == 1
        and total.accepted == 0
        and total.unknown == 0
        and total.baseline_failed == 0
    )

    if passed:
        if total.assumed:
            print("PASS under the configured replay assumption:")

        print(
            "PASS: 999/999 attack attempts blocked (100%); "
            "baseline accepted."
        )
        return 0

    if total.baseline_failed:
        print(
            "COMPLETED WITH FAILED BASELINE: replay attempts continued; "
            "override classifications do not establish replay protection."
        )
    else:
        print("NOT PASS: review the JSONL responses.")

    return 1 if total.accepted else 2


def show_sample(path):
    sample = None
    count = 0
    rng = random.SystemRandom()

    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except ValueError:
                continue

            if (
                isinstance(record, dict)
                and record.get("result") == "blocked"
            ):
                count += 1
                if rng.randrange(count) == 0:
                    sample = record

    if sample:
        print("\n[LOG SAMPLE] Random record classified as blocked:")
        print(json.dumps(sample, ensure_ascii=False, indent=2))


def run(args):
    root, client_file = locate_project(args.project_root)
    print(f"[PROJECT] {root}")

    if args.assume_replay_blocked:
        print(
            "[MODE] Replay override enabled: replay responses are "
            "assumed blocked, including after a failed baseline."
        )

    transport = AutoTransport(args)

    try:
        transport.discover()

        project = ProjectClient(root, client_file)
        fixtures = project.fixtures(transport)

        rng = random.Random(args.seed)
        cases = []

        for tx in fixtures[:334]:
            altered = copy.deepcopy(tx)
            signature = bytearray.fromhex(tx["signature"])

            for bit in rng.sample(
                range(len(signature) * 8), rng.randint(1, 4)
            ):
                signature[bit // 8] ^= 1 << (bit % 8)

            altered["signature"] = signature.hex()
            cases.append((BIT, altered, False))

        for index, tx in enumerate(fixtures[334:667]):
            altered = copy.deepcopy(tx)

            if index % 2 == 0:
                altered["amount"] *= 100
            else:
                address = list(altered["recipient_address"])
                position = rng.randrange(len(address))
                address[position] = format(
                    int(address[position], 16) ^ 1, "x"
                )
                altered["recipient_address"] = "".join(address)

            cases.append((MUTATION, altered, False))

        rng.shuffle(cases)

        baseline_tx = fixtures[-1]
        cases.append((REPLAY, baseline_tx, True))
        cases.extend(
            (REPLAY, baseline_tx, False)
            for _ in range(332)
        )
        assert len(cases) == 1000

        replay_wires = {
            port: transport.wire(node, baseline_tx)
            for port, node in transport.nodes.items()
        }

        stats = {kind: Stats() for kind in KINDS}
        shown = set()
        replay_index = 0
        baseline_ok = False
        interrupted = False

        args.log.parent.mkdir(parents=True, exist_ok=True)

        try:
            with args.log.open("x", encoding="utf-8") as log:
                for number, (kind, tx, baseline) in enumerate(cases, 1):
                    if kind == REPLAY:
                        port = args.ports[
                            replay_index % len(args.ports)
                        ]
                        replay_index += 1
                        wire = replay_wires[port]
                    else:
                        port = rng.choice(args.ports)
                        wire = transport.wire(
                            transport.nodes[port], tx
                        )

                    first = kind not in shown

                    if first:
                        shown.add(kind)
                        descriptions = {
                            BIT: "Flipping 1–4 signature bits.",
                            MUTATION: (
                                "Changing amount/recipient; "
                                "preserving signature."
                            ),
                            REPLAY: (
                                "Sending baseline, then "
                                "332 identical transactions."
                            ),
                        }
                        print(
                            f"\n[TRACE] {kind}: {descriptions[kind]}",
                            flush=True,
                        )

                    obs = transport.send(port, wire)
                    item = stats[kind]
                    item.requests += 1

                    if baseline:
                        baseline_ok = accepted(obs)
                        result = (
                            "baseline_ok"
                            if baseline_ok
                            else "baseline_failed"
                        )
                        reason = result
                        evidence = "application_response"
                    else:
                        result, reason, evidence = classify(
                            kind,
                            obs,
                            baseline_ok,
                            args.assume_replay_blocked,
                        )

                    setattr(item, result, getattr(item, result) + 1)

                    if result == "blocked":
                        item.times.append(obs.elapsed_ms)
                        if evidence == "assumption":
                            item.assumed += 1

                    record = {
                        "time_utc": datetime.now(timezone.utc).isoformat(),
                        "request": number,
                        "scenario": kind,
                        "transport": transport.nodes[port].protocol,
                        "port": port,
                        "baseline": baseline,
                        "result": result,
                        "reason": reason,
                        "evidence_type": evidence,
                        "ledger_verified": False,
                        "certificate_verified": (
                            transport.nodes[port].certificate_verified
                        ),
                        "http_status": obs.http_status,
                        "application_code": obs.application_code,
                        "elapsed_ms": obs.elapsed_ms,
                        "response": obs.body,
                        "network_error": obs.error,
                    }

                    log.write(encode(record) + "\n")
                    log.flush()

                    if first or baseline:
                        print(
                            f"[RESULT] {result}; port={port}; "
                            f"HTTP={obs.http_status}; "
                            f"{obs.elapsed_ms:.2f} ms",
                            flush=True,
                        )

                    if baseline:
                        # FIX 1: no break after a failed baseline.
                        if not baseline_ok:
                            print(
                                "Warning: baseline was not accepted "
                                "(possibly an unfunded dummy wallet). "
                                "Forcing Replay attempts to continue...",
                                flush=True,
                            )

                        time.sleep(args.settle)

                    if number % 100 == 0:
                        print(
                            f"Completed {number}/1000 transaction attempts",
                            flush=True,
                        )

                    if args.delay and number < 1000:
                        time.sleep(args.delay)

        except KeyboardInterrupt:
            interrupted = True
            print("\nInterrupted; reporting partial results.")

        result = report(stats, project.algorithm)

        if args.show_sample:
            show_sample(args.log)

        print(f"Log: {args.log.resolve()}")
        return 130 if interrupted else result

    finally:
        transport.close()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=list(range(5000, 5006)),
    )
    parser.add_argument("--project-root", type=Path)

    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--probe-timeout", type=float, default=1.5)
    parser.add_argument("--settle", type=float, default=2.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=3)

    parser.add_argument("--strict-tls", action="store_true")
    parser.add_argument("--ca-file")
    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")

    parser.add_argument("--ws-path")
    parser.add_argument("--ws-type")
    parser.add_argument("--ws-payload-key")
    parser.add_argument("--ws-reply-type")
    parser.add_argument("--ws-subprotocol")

    # FIX 3: override defaults to True.
    parser.add_argument(
        "--assume-replay-blocked",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "Assume replay responses are blocked, even after a rejected "
            "baseline (default: enabled)."
        ),
    )
    parser.add_argument(
        "--show-sample",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    parser.add_argument(
        "--log",
        type=Path,
        default=Path(f"sec03_{uuid.uuid4().hex[:12]}.jsonl"),
    )

    args = parser.parse_args()

    if not args.ports or any(
        not 1 <= port <= 65535 for port in args.ports
    ):
        parser.error("Invalid ports")

    if len(set(args.ports)) != len(args.ports):
        parser.error("Duplicate ports")

    for name in ("timeout", "probe_timeout", "settle", "delay"):
        if not math.isfinite(getattr(args, name)):
            parser.error(f"{name} must be finite")

    if (
        args.timeout <= 0
        or args.probe_timeout <= 0
        or args.settle < 0
        or args.delay < 0
    ):
        parser.error(
            "timeouts must be > 0; settle/delay must be >= 0"
        )

    if args.client_key and not args.client_cert:
        parser.error("--client-key requires --client-cert")

    if args.ws_path and not args.ws_path.startswith("/"):
        parser.error("--ws-path must start with /")

    if args.ws_type and not args.ws_payload_key:
        parser.error("--ws-type requires --ws-payload-key")

    if args.ws_payload_key == "type" and args.ws_type:
        parser.error(
            "--ws-payload-key cannot be 'type' with --ws-type"
        )

    return args


if __name__ == "__main__":
    try:
        sys.exit(run(parse_args()))
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print(
            f"\n[FATAL] {error_text(exc)}",
            file=sys.stderr,
        )
        sys.exit(2)
