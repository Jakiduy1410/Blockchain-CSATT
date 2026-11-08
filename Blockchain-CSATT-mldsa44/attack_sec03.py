#!/usr/bin/env python3
"""
SEC-03 automated transaction mutation testing.

Run:
    python3 attack_sec03.py

Terminal output:
    [SIGNER]
    [TX 0001/1450]
    [BIT DISTRIBUTION]
    [LEDGER]
    [RESULT]
    SEC-03 RESULTS

Detailed records are written to JSONL, terminal log, PNG chart, and summary JSON.

Normal completion (per signature algorithm):
    300 bit-flipped + 300 valid transactions
    300 mutated-payload + 300 valid transactions
    50 original transactions + 200 replay attempts (4 per original)

Replay classification checks ledger state; an HTTP 201 alone does not prove
that a duplicate was inserted. Rejected transactions cannot be in a block.
The sender wallet must have at least 22 coins available on the live ledger.

Dependencies:
    requests
    matplotlib
    Project Flask / cryptographic dependencies
    websockets>=15 only when WSS is needed
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
import math
import os
import random
import re
import ssl
import sys
import threading
import time
import unicodedata
import uuid
from collections import Counter

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

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

# Public-key bytes and signature bytes for standardized ML-DSA variants.
ML_DSA_SIZES = {
    "ML-DSA-44": (1312, 2420),
    "ML-DSA-65": (1952, 3309),
    "ML-DSA-87": (2592, 4627),
}


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


# ==================== ALGORITHM IDENTIFICATION ====================

def canonical_algorithm(value: Any) -> str | None:
    """Convert recognizable algorithm names to one of the five labels."""
    if not isinstance(value, str):
        return None

    compact = re.sub(r"[^A-Z0-9]", "", value.upper())

    for parameter in ("44", "65", "87"):
        if f"MLDSA{parameter}" in compact:
            return f"ML-DSA-{parameter}"

    # Test ECDSA before RSA.
    if "ECDSA" in compact:
        return "ECDSA"

    if "RSA" in compact:
        return "RSA"

    return None


def inspect_public_key(public_key: bytes) -> str | None:
    """Prefer actual RSA/ECC key parsing over length-only heuristics."""
    try:
        from Crypto.PublicKey import RSA
    except ImportError:
        RSA = None

    if RSA is not None:
        try:
            RSA.import_key(public_key)
            return "RSA"
        except (ValueError, TypeError, IndexError):
            pass

    try:
        from Crypto.PublicKey import ECC
    except ImportError:
        ECC = None

    if ECC is not None:
        try:
            key = ECC.import_key(public_key)
            curve = str(getattr(key, "curve", "")).lower()

            # Don't label EdDSA/Montgomery keys as ECDSA.
            if "ed25519" not in curve and "ed448" not in curve:
                if "curve25519" not in curve and "curve448" not in curve:
                    return "ECDSA"
        except (ValueError, TypeError, IndexError, NotImplementedError):
            pass

    # Optional second parser, useful for DER-encoded EC keys.
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
    except ImportError:
        return None

    try:
        if public_key.startswith(b"-----BEGIN"):
            key = serialization.load_pem_public_key(public_key)
        else:
            key = serialization.load_der_public_key(public_key)

        if isinstance(key, rsa.RSAPublicKey):
            return "RSA"

        if isinstance(key, ec.EllipticCurvePublicKey):
            return "ECDSA"

    except (ValueError, TypeError):
        pass

    return None


def detect_algorithm(
    declared_names: list[str],
    root: Path,
    source: Path,
    public_key_hex: str,
    signature_hex: str,
) -> str:
    public_key = decode_hex(public_key_hex, "public_key")
    signature = decode_hex(signature_hex, "signature")

    public_size = len(public_key)
    signature_size = len(signature)

    # Exact ML-DSA key/signature size pairs.
    size_algorithm = next(
        (
            algorithm
            for algorithm, sizes in ML_DSA_SIZES.items()
            if sizes == (public_size, signature_size)
        ),
        None,
    )

    # Parse classical key formats when possible.
    parsed_algorithm = inspect_public_key(public_key)

    # Only unambiguous declarations are used.
    declared = {
        algorithm
        for name in declared_names
        if (algorithm := canonical_algorithm(name)) is not None
    }
    declared_algorithm = next(iter(declared)) if len(declared) == 1 else None

    evidence_algorithm = size_algorithm or parsed_algorithm

    if (
        declared_algorithm
        and evidence_algorithm
        and declared_algorithm != evidence_algorithm
    ):
        raise RuntimeError(
            "Algorithm mismatch: project declares "
            f"{declared_algorithm}, but key/signature indicate "
            f"{evidence_algorithm}."
        )

    if evidence_algorithm:
        return evidence_algorithm

    if declared_algorithm:
        if declared_algorithm in ML_DSA_SIZES:
            expected = ML_DSA_SIZES[declared_algorithm]
            if expected != (public_size, signature_size):
                raise RuntimeError(
                    f"{declared_algorithm} size mismatch: "
                    f"public_key={public_size}, signature={signature_size}; "
                    f"expected {expected}."
                )
        return declared_algorithm

    # Common formats in the RSA/ECDSA project variants.
    if public_size == 64:
        return "ECDSA"

    # 162 bytes is a common DER public-key encoding for RSA-1024.
    # Require the matching 128-byte signature as additional evidence.
    if public_size == 162 and signature_size == 128:
        return "RSA"

    # Last resort: project directory name, not unrelated ancestor folders.
    for directory_name in (root.name, source.parent.name):
        algorithm = canonical_algorithm(directory_name)
        if algorithm is None:
            continue

        if algorithm in ML_DSA_SIZES:
            if ML_DSA_SIZES[algorithm] != (public_size, signature_size):
                continue

        return algorithm

    raise RuntimeError(
        "Cannot identify RSA/ECDSA/ML-DSA-44/ML-DSA-65/ML-DSA-87 "
        f"from the project configuration or key format "
        f"(public_key={public_size} bytes, signature={signature_size} bytes)."
    )


# ==================== TRANSPORT ====================

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
    lock: Any = field(default_factory=threading.Lock, repr=False)


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
        self.discovery_errors: dict[int, list[str]] = {}

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
                )

                try:
                    with self.open_ws(candidate) as ws:
                        if not ws.ping().wait(self.args.probe_timeout):
                            raise TimeoutError("WebSocket Pong timeout")
                    return candidate

                except Exception as exc:
                    errors.append(f"wss {path}: {error_text(exc)}")

        if self.connect_ws is None:
            errors.append(
                'WSS unavailable: install "websockets>=15".'
            )

        self.discovery_errors[port] = errors
        return None

    def discover(self):
        failures = []

        for port in self.args.ports:
            node = self.discover_node(port)

            if node is None:
                failures.append(port)
            else:
                self.nodes[port] = node

        if failures:
            details = []
            for port in failures:
                errors = self.discovery_errors.get(port, [])
                details.append(
                    f"port {port}: "
                    + (" | ".join(errors) or "no supported transport")
                )

            raise RuntimeError(
                "Pre-check failed; no transaction tests were sent.\n"
                + "\n".join(details)
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
                f"[RESULT] NETWORK ERROR port={port}: {error}",
                file=sys.stderr,
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


# ==================== PROJECT CLIENT / FIXTURES ====================

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
    public_key: str
    private_key: str
    balance: float
    balance_source: str


class ProjectClient:
    def __init__(self, root, source):
        self.root = root
        self.source = source
        self.algorithm = None

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

        self.declared_algorithms = [
            value
            for attribute in (
                "SIG_ALG",
                "SIGNATURE_ALGORITHM",
                "SIGNATURE_SCHEME",
                "ALGORITHM",
                "SIG_ALGORITHM",
            )
            if isinstance(value := getattr(module, attribute, None), str)
        ]

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

        def visit(value, depth=0):
            if depth > 12:
                return

            if isinstance(value, list):
                for entry in value:
                    visit(entry, depth + 1)
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
                                public_key=public,
                                private_key=private,
                                balance=balance,
                                balance_source=balance_source,
                            )
                        )

                except (ValueError, TypeError):
                    pass

            for entry in value.values():
                if isinstance(entry, (dict, list)):
                    visit(entry, depth + 1)

        for path in self.wallet_files():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError):
                continue

            visit(data)

        candidates.sort(
            key=lambda wallet: (
                wallet.balance_source == "live API",
                wallet.balance,
            ),
            reverse=True,
        )

        return candidates

    def fixtures(self, transport):
        recipient = self.new_wallet()["public_key"]
        expected_size = len(decode_hex(recipient, "recipient"))
        candidates = self.discover_wallets(transport.balances())

        selected = None
        baseline = None

        for wallet in candidates:
            if wallet.balance_source != "live API" or wallet.balance < 22:
                continue
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
            raise RuntimeError(
                "No funded wallet with a matching private key and at least "
                "22 coins in the live /accounts/balance response."
            )

        self.algorithm = detect_algorithm(
            declared_names=self.declared_algorithms,
            root=self.root,
            source=self.source,
            public_key_hex=selected.public_key,
            signature_hex=baseline["signature"],
        )

        # All 650 legitimate transfers together spend 21.1575 coins.
        # Distinct signed amounts also keep transaction IDs distinct because
        # this network does not include the client's nonce in its tx hash.
        if selected.balance < 22:
            raise RuntimeError(
                f"Funded test wallet required (available={selected.balance}; "
                "need at least 22 coins for 650 legitimate transfers)."
            )
        amounts = (
            list(range(651, 951)) + list(range(1, 301))
            + list(range(951, 1251)) + list(range(301, 651))
        )
        fixtures = [
            self.sign(selected, recipient, f"{amount / 10000:.4f}")
            for amount in amounts
        ]

        if self.algorithm in ML_DSA_SIZES:
            expected_public, expected_signature = ML_DSA_SIZES[self.algorithm]

            if len(decode_hex(selected.public_key, "public_key")) != expected_public:
                raise RuntimeError(
                    f"Unexpected {self.algorithm} public-key size"
                )

            if any(
                len(decode_hex(tx["signature"], "signature"))
                != expected_signature
                for tx in fixtures
            ):
                raise RuntimeError(
                    f"Unexpected {self.algorithm} signature size"
                )

        return fixtures


# ==================== CLASSIFICATION ====================

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


def classify_attack(obs):
    if obs.error:
        return "unknown", "transport_error", "transport"

    code = (
        obs.http_status
        if obs.http_status is not None
        else obs.application_code
    )
    body = obs.body if isinstance(obs.body, dict) else {}

    if (
        code == 406
        or str(body.get("status", "")).lower() in REJECTED
        or body.get("accepted") is False
    ):
        return "blocked", "transaction_rejected", "response"

    if accepted(obs):
        return "accepted", "application_acceptance", "response"

    return "unknown", "unrecognized_response", "response"


@dataclass
class Case:
    kind: str
    tx: dict
    attack: bool
    bits: int = 0
    source_id: int | None = None
    mutation_field: str | None = None


def tx_key(tx):
    return (
        str(tx.get("sender_address", "")),
        str(tx.get("recipient_address", "")),
        str(tx.get("value", tx.get("amount", ""))),
        str(tx.get("signature", "")),
    )


def tx_id(tx):
    sender, recipient, value, signature = tx_key(tx)
    return hashlib.sha256(
        f"{sender}:{recipient}:{value}:{signature}".encode("utf-8")
    ).hexdigest()


def ledger_snapshot(transport, port):
    """Read one node's chain and mempool; None means verification unavailable."""
    node = transport.nodes[port]
    if node.protocol not in {"http", "https"}:
        return None
    try:
        base = transport.url(node.protocol, port, "")
        chain_response = node.session.get(
            base + "/chain", timeout=transport.args.timeout
        )
        pool_response = node.session.get(
            base + "/transactions/get", timeout=transport.args.timeout
        )
        chain_response.raise_for_status()
        pool_response.raise_for_status()
        chain = chain_response.json()["chain"]
        pool = pool_response.json()["transactions"]
        if not isinstance(chain, list) or not isinstance(pool, list):
            return None
        confirmed = Counter(
            tx_key(tx)
            for block in chain
            for tx in block.get("transactions", [])
        )
        pending = Counter(tx_key(tx) for tx in pool)
        return confirmed, pending
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return None


def ledger_count(snapshot, tx):
    if snapshot is None:
        return None
    key = tx_key(tx)
    return snapshot[0][key] + snapshot[1][key]


def recent_node_audit(transport, port):
    """Best-effort snapshot; node audit entries may include concurrent traffic."""
    node = transport.nodes[port]
    if node.protocol not in {"http", "https"}:
        return None
    try:
        response = node.session.get(
            transport.url(node.protocol, port, "/audit/logs"),
            params={"limit": 8},
            timeout=transport.args.timeout,
        )
        response.raise_for_status()
        entries = response.json().get("logs")
        return entries if isinstance(entries, list) else None
    except (requests.RequestException, ValueError, TypeError, AttributeError):
        return None


def make_cases(fixtures, rng):
    assert len(fixtures) == 1250
    bit_cases = []
    mutation_cases = []
    replay_groups = []
    bit_counts = [1, 2, 3, 4] * 75
    rng.shuffle(bit_counts)
    for tx, count in zip(fixtures[:300], bit_counts):
        altered = copy.deepcopy(tx)
        signature = bytearray.fromhex(tx["signature"])
        for bit in rng.sample(range(len(signature) * 8), count):
            signature[bit // 8] ^= 1 << (bit % 8)
        altered["signature"] = signature.hex()
        bit_cases.append(Case(BIT, altered, True, bits=count))
    bit_cases.extend(Case(BIT, tx, False) for tx in fixtures[300:600])
    rng.shuffle(bit_cases)

    for index, tx in enumerate(fixtures[600:900]):
        altered = copy.deepcopy(tx)
        if index % 2 == 0:
            mutation_field = "amount"
            replacement = float(tx[mutation_field]) * 100
        else:
            mutation_field = "recipient_address"
            address = list(tx[mutation_field])
            position = rng.randrange(len(address))
            address[position] = format(int(address[position], 16) ^ 1, "x")
            replacement = "".join(address)
        # Keep the existing random draws before redirecting one in three cases.
        if index % 3 == 0:
            mutation_field = "sender_address"
            # Reuse the generated recipient public key as a valid alternate sender.
            replacement = tx["recipient_address"]
        altered[mutation_field] = replacement
        mutation_cases.append(Case(MUTATION, altered, True, mutation_field=mutation_field))
    mutation_cases.extend(Case(MUTATION, tx, False)
                          for tx in fixtures[900:1200])
    rng.shuffle(mutation_cases)

    for source_id, tx in enumerate(fixtures[1200:], 1):
        replay_groups.append([Case(REPLAY, tx, False, source_id=source_id)]
                             + [Case(REPLAY, tx, True, source_id=source_id)
                                for _ in range(4)])
    rng.shuffle(replay_groups)
    cases = {
        BIT: bit_cases,
        MUTATION: mutation_cases,
        REPLAY: [case for group in replay_groups for case in group],
    }
    assert [len(cases[kind]) for kind in KINDS] == [600, 600, 250]
    return cases, Counter(bit_counts)


def write_latency_chart(path, samples, fields, title, color):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    grouped = {field: [] for field in fields}
    for field, latency in samples:
        grouped[field].append(latency)

    fig, ax = plt.subplots(figsize=(8, 4.5))
    try:
        for position, field in enumerate(fields):
            values = grouped[field]
            if values:
                bars = ax.bar(position, math.fsum(values) / len(values),
                              width=0.56, color=color)
                ax.bar_label(bars, fmt="%.2f ms", padding=4)
            else:
                ax.text(position, 0.04, "N/A", ha="center",
                        transform=ax.get_xaxis_transform())
        ax.set_xticks(range(len(fields)), [f"{label}\n(n={len(grouped[field])})"
                                          for field, label in fields.items()])
        ax.set_xlim(-0.5, len(fields) - 0.5)
        ax.set_ylim(bottom=0)
        ax.margins(y=0.2)
        ax.set_title(title)
        ax.set_ylabel("Thời gian chặn trung bình (ms)")
        ax.set_axisbelow(True)
        ax.grid(axis="y", alpha=0.22)
        fig.tight_layout()
        fig.savefig(path, format="png", dpi=180)
    finally:
        plt.close(fig)


def write_bit_chart(path, samples):
    fields = {bits: f"{bits} bit" for bits in range(1, 5)}
    write_latency_chart(path, samples, fields,
                        "Bit-flipping · Độ trễ theo số bit bị lật", "#2563eb")


def write_mutation_chart(path, samples):
    fields = {"amount": "Sửa Amount", "recipient_address": "Sửa Receiver",
              "sender_address": "Sửa Sender"}
    write_latency_chart(path, samples, fields,
                        "Payload mutation · Độ trễ theo trường bị sửa", "#158379")


def write_replay_chart(path, samples):
    import matplotlib.pyplot as plt

    points = [(index, latency) for index, latency in enumerate(samples, 1)
              if latency is not None]
    fig, ax = plt.subplots(figsize=(9, 4.5))
    try:
        ax.scatter([index for index, _ in points], [latency for _, latency in points],
                   color="#3169b0", s=15, alpha=0.8)
        ax.set_xlim(0.5, max(1, len(samples)) + 0.5)
        ax.set_ylim(bottom=0)
        ax.set_title(f"Replay · {len(points)}/{len(samples)} yêu cầu bị chặn")
        ax.set_xlabel("Thứ tự yêu cầu replay")
        ax.set_ylabel("Độ trễ phản hồi (ms)")
        ax.set_axisbelow(True)
        ax.grid(alpha=0.22)
        fig.tight_layout()
        fig.savefig(path, format="png", dpi=180)
    finally:
        plt.close(fig)


# ==================== EXECUTION ====================

def configured_miner_port(root, ports):
    config = root / "configs" / "network_6nodes.json"
    if config.is_file():
        try:
            nodes = json.loads(config.read_text(encoding="utf-8"))["nodes"]
            for node in nodes:
                if node.get("is_miner") and node.get("port") in ports:
                    return node["port"]
        except (OSError, ValueError, KeyError, TypeError):
            pass
    return ports[0]


def confirm_in_blocks(transport, port, normal_cases, timeout, mine):
    """Wait for this phase's legitimate transactions to enter the miner chain."""
    expected = {tx_key(case.tx) for case in normal_cases}
    deadline = time.monotonic() + timeout
    last_snapshot = None
    while time.monotonic() < deadline:
        snapshot = ledger_snapshot(transport, port)
        if snapshot is None:
            time.sleep(0.25)
            continue
        last_snapshot = snapshot
        if all(snapshot[0][key] == 1 for key in expected):
            return snapshot

        pending = any(snapshot[1][key] for key in expected)
        if pending and mine:
            node = transport.nodes[port]
            try:
                response = node.session.get(
                    transport.url(node.protocol, port, "/mine"),
                    timeout=max(transport.args.timeout, 30),
                )
                response.raise_for_status()
            except requests.RequestException as exc:
                print(f"[MINER] Không đào được block: {error_text(exc)}",
                      flush=True)
                time.sleep(0.5)
        else:
            time.sleep(0.25)
    return last_snapshot


def phase_summary(kind, records, snapshot, wall_seconds):
    attacks = [(case, row) for case, row in records if case.attack]
    normals = [(case, row) for case, row in records if not case.attack]
    blocked_times = [row["elapsed_ms"] for _, row in attacks
                     if row["result"] == "blocked"]
    blocked = len(blocked_times)
    slipped = sum(row["result"] == "accepted" for _, row in attacks)
    unknown = len(attacks) - blocked - slipped
    original_accepted = sum(row["result"] == "accepted"
                            for _, row in normals)
    in_block = in_pool = missing = 0
    bad_in_ledger = replay_duplicates = 0
    if snapshot is not None:
        for case, _ in normals:
            key = tx_key(case.tx)
            if snapshot[0][key] == 1:
                in_block += 1
            elif snapshot[1][key]:
                in_pool += 1
            else:
                missing += 1
        if kind == REPLAY:
            replay_duplicates = sum(
                max(0, ledger_count(snapshot, case.tx) - 1)
                for case, _ in normals
            )
        else:
            bad_in_ledger = sum(
                bool(ledger_count(snapshot, case.tx))
                for case, _ in attacks
            )

    wanted_normals = 50 if kind == REPLAY else 300
    wanted_attacks = 200 if kind == REPLAY else 300
    passed = (
        len(normals) == wanted_normals
        and len(attacks) == wanted_attacks
        and blocked == wanted_attacks
        and slipped == unknown == 0
        and original_accepted == wanted_normals
        and in_block == wanted_normals
        and in_pool == missing == bad_in_ledger == replay_duplicates == 0
    )
    return {
        "scenario": kind,
        "normal_sent": len(normals),
        "attack_sent": len(attacks),
        "normal_accepted": original_accepted,
        "normal_in_block": in_block,
        "normal_in_mempool": in_pool,
        "normal_missing": missing,
        "attack_blocked": blocked,
        "attack_slipped": slipped,
        "attack_unknown": unknown,
        "attack_in_ledger": bad_in_ledger,
        "replay_duplicates": replay_duplicates,
        "blocked_latency_mean_ms": (
            round(math.fsum(blocked_times) / len(blocked_times), 3)
            if blocked_times else None
        ),
        "blocked_latency_total_ms": round(math.fsum(blocked_times), 3),
        "phase_wall_seconds": round(wall_seconds, 3),
        "ledger_verified": snapshot is not None,
        "passed": passed,
    }


def mixed_phase_results(transport, cases, ports, rng, workers, delay):
    """Send a shuffled phase concurrently, with one active request per node."""
    assignments = [(case, rng.choice(ports)) for case in cases]

    def send_assigned(assignment):
        case, port = assignment
        node = transport.nodes[port]
        with node.lock:
            obs = transport.send(port, transport.wire(node, case.tx))
            response_time = datetime.now(timezone.utc).isoformat()
            audit = recent_node_audit(transport, port)
            if delay:
                time.sleep(delay)
        return case, port, obs, None, None, audit, response_time

    with ThreadPoolExecutor(max_workers=workers) as executor:
        yield from executor.map(send_assigned, assignments)


def replay_phase_results(transport, cases, port, settle, delay):
    """Keep every original before its four replays on the same node."""
    node = transport.nodes[port]
    for case in cases:
        before = ledger_snapshot(transport, port) if case.attack else None
        obs = transport.send(port, transport.wire(node, case.tx))
        response_time = datetime.now(timezone.utc).isoformat()
        after = ledger_snapshot(transport, port) if case.attack else None
        audit = recent_node_audit(transport, port)
        yield case, port, obs, before, after, audit, response_time
        if not case.attack and settle:
            time.sleep(settle)
        if delay:
            time.sleep(delay)


def run(args):
    root, client_file = locate_project(args.project_root)
    transport = AutoTransport(args)
    try:
        transport.discover()
        miner_port = args.miner_port or configured_miner_port(root, args.ports)
        if miner_port not in transport.nodes:
            raise RuntimeError(f"Miner port {miner_port} không có trong --ports")
        if transport.nodes[miner_port].protocol not in {"http", "https"}:
            raise RuntimeError("Đối chiếu block và đào block cần HTTP(S) REST")
        if ledger_snapshot(transport, miner_port) is None:
            raise RuntimeError("Không đọc được /chain và /transactions/get trên miner")

        project = ProjectClient(root, client_file)
        fixtures = project.fixtures(transport)
        rng = random.Random(args.seed)
        phases, planned_bits = make_cases(fixtures, rng)
        args.log.parent.mkdir(parents=True, exist_ok=True)
        terminal_path = args.log.with_suffix(".terminal.log")
        summary_path = args.log.with_suffix(".summary.json")
        chart_path = args.log.with_suffix(".bits.png")
        number = 0
        summaries = []
        bit_counts = Counter()
        replay_baselines = {}
        bit_samples = []
        mutation_samples = []
        replay_samples = []

        output_paths = [args.log, terminal_path, chart_path,
                        args.log.with_suffix(".mutation.png"),
                        args.log.with_suffix(".replay.png"), summary_path]
        output_token = uuid.uuid4().hex
        temporary_paths = {
            path: path.with_name(f"{path.name}.{output_token}.tmp")
            for path in output_paths
        }
        with temporary_paths[args.log].open("x", encoding="utf-8") as log, \
                temporary_paths[terminal_path].open("x", encoding="utf-8") as terminal:
            def emit(message):
                print(message, flush=True)
                terminal.write(message + "\n")
                terminal.flush()

            emit(f"[SIGNER] {project.algorithm} | miner={miner_port} "
                 "| tổng 1450 yêu cầu")
            for kind in KINDS:
                cases = phases[kind]
                records = []
                started = time.monotonic()
                emit(f"\n[PHASE] {kind}: {len(cases)} giao dịch đã trộn "
                     f"| workers={args.workers if kind != REPLAY else 1}")
                iterator = (
                    replay_phase_results(
                        transport, cases, miner_port, args.settle, args.delay
                    ) if kind == REPLAY else mixed_phase_results(
                        transport, cases, args.ports, rng,
                        args.workers, args.delay,
                    )
                )
                for case, port, obs, before, after, audit, response_time in iterator:
                    number += 1
                    node = transport.nodes[port]

                    if kind == REPLAY and not case.attack:
                        result = "accepted" if accepted(obs) else (
                            "unknown" if obs.error else "blocked"
                        )
                        reason = "original_transaction"
                        evidence = "response"
                        replay_baselines[case.source_id] = result == "accepted"
                    elif kind == REPLAY:
                        before_count = ledger_count(before, case.tx)
                        after_count = ledger_count(after, case.tx)
                        if not replay_baselines.get(case.source_id):
                            result, reason, evidence = (
                                "unknown", "original_not_accepted", "response")
                        elif before_count == after_count == 1:
                            result, reason, evidence = (
                                "blocked", "duplicate_not_inserted", "ledger")
                        elif (before_count is not None
                              and after_count is not None
                              and (after_count > before_count
                                   or after_count > 1)):
                            result, reason, evidence = (
                                "accepted", "duplicate_inserted", "ledger")
                        elif duplicate_reply(obs.body):
                            result, reason, evidence = (
                                "blocked", "explicit_duplicate_response", "response")
                        else:
                            result, reason, evidence = (
                                "unknown", "ledger_unavailable_or_transition",
                                "ledger")
                    elif case.attack:
                        result, reason, evidence = classify_attack(obs)
                    else:
                        result = "accepted" if accepted(obs) else (
                            "unknown" if obs.error else "blocked")
                        reason = "normal_transaction"
                        evidence = "response"

                    if kind == BIT and case.attack:
                        bit_counts[case.bits] += 1
                    status = (
                        "BỊ CHẶN" if case.attack and result == "blocked"
                        else "LỌT QUA" if case.attack and result == "accepted"
                        else "TIẾP NHẬN" if not case.attack and result == "accepted"
                        else "BỊ TỪ CHỐI" if not case.attack and result == "blocked"
                        else "CHƯA RÕ"
                    )
                    row = {
                        "time_utc": response_time,
                        "request": number,
                        "algorithm": project.algorithm,
                        "scenario": kind,
                        "group": "attack" if case.attack else "normal",
                        "bit_flips": case.bits or None,
                        "replay_source": case.source_id,
                        "tx_id": tx_id(case.tx),
                        "port": port,
                        "transport": node.protocol,
                        "result": result,
                        "reason": reason,
                        "evidence_type": evidence,
                        "http_status": obs.http_status,
                        "application_code": obs.application_code,
                        "elapsed_ms": obs.elapsed_ms,
                        "response": obs.body,
                        "network_error": obs.error,
                        "ledger_count_before": ledger_count(before, case.tx),
                        "ledger_count_after": ledger_count(after, case.tx),
                        "node_audit_recent": audit,
                    }
                    if case.mutation_field is not None:
                        row["mutation_field"] = case.mutation_field
                    log.write(encode(row) + "\n")
                    log.flush()
                    records.append((case, row))
                    emit(f"[TX {number:04d}/1450] {kind:<16} "
                         f"{'ATTACK' if case.attack else 'NORMAL':<6} "
                         f"port={port} HTTP={obs.http_status} {status:<12} "
                         f"latency={obs.elapsed_ms:.2f}ms {reason}")

                if kind == BIT:
                    emit("[BIT DISTRIBUTION] " + ", ".join(
                        f"{bits} bit={bit_counts[bits]}"
                        for bits in range(1, 5)
                    ))
                normal_cases = [case for case in cases if not case.attack]
                snapshot = confirm_in_blocks(
                    transport, miner_port, normal_cases,
                    args.confirm_timeout, args.mine,
                )
                summary = phase_summary(
                    kind, records, snapshot,
                    time.monotonic() - started,
                )
                summaries.append(summary)
                if kind == BIT:
                    bit_samples = [(case.bits, row["elapsed_ms"])
                                   for case, row in records
                                   if case.attack and row["result"] == "blocked"]
                elif kind == MUTATION:
                    mutation_samples = [(case.mutation_field, row["elapsed_ms"])
                                        for case, row in records
                                        if case.attack and row["result"] == "blocked"]
                elif kind == REPLAY:
                    replay_samples = [row["elapsed_ms"] if row["result"] == "blocked" else None
                                      for case, row in records if case.attack]
                emit(f"[CHỐT] {kind}: tấn công bị chặn="
                     f"{summary['attack_blocked']}/{summary['attack_sent']}, "
                     f"lọt qua={summary['attack_slipped']}, "
                     f"chưa rõ={summary['attack_unknown']}; giao dịch hợp lệ "
                     f"vào block={summary['normal_in_block']}/"
                     f"{summary['normal_sent']} (mempool="
                     f"{summary['normal_in_mempool']}, thiếu="
                     f"{summary['normal_missing']}); độ trễ chặn TB="
                     f"{summary['blocked_latency_mean_ms']} ms")
                emit("[CHỐT] " + ("PASS" if summary["passed"] else "NOT PASS"))

            passed = all(item["passed"] for item in summaries)
            emit("\n[RESULT] " + ("PASS" if passed else "NOT PASS")
                 + f" | thuật toán={project.algorithm}")
            emit(f"[FILES] {args.log} | {terminal_path} | "
                 f"{chart_path} | {summary_path}")

        temporary_paths[summary_path].write_text(encode({
            "algorithm": project.algorithm,
            "passed": passed,
            "expected_requests": 1450,
            "observed_requests": number,
            "bit_flip_distribution": {str(bit): bit_counts[bit]
                                      for bit in range(1, 5)},
            "bit_flip_plan": {str(bit): planned_bits[bit]
                              for bit in range(1, 5)},
            "scenarios": summaries,
            "log": str(args.log),
            "terminal_log": str(terminal_path),
            "chart": str(chart_path),
        }) + "\n", encoding="utf-8")
        outputs_ready = True
        for suffix, draw, samples in (
            (".bits.png", write_bit_chart, bit_samples),
            (".mutation.png", write_mutation_chart, mutation_samples),
            (".replay.png", write_replay_chart, replay_samples),
        ):
            path = args.log.with_suffix(suffix)
            try:
                draw(temporary_paths[path], samples)
            except Exception as exc:
                outputs_ready = False
                print(f"[CHART] Không lưu được {path}: {exc}", file=sys.stderr)
            else:
                print(f"[CHART] {path}")
    finally:
        transport.close()
    if passed and outputs_ready:
        for path, temporary in temporary_paths.items():
            os.replace(temporary, path)
    return 0 if passed and outputs_ready else 1


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
    parser.add_argument("--miner-port", type=int)
    parser.add_argument("--confirm-timeout", type=float, default=120.0)
    parser.add_argument(
        "--no-mine", dest="mine", action="store_false",
        help="Chỉ đợi miner tự động; không gọi /mine thủ công.",
    )
    parser.set_defaults(mine=True)

    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--probe-timeout", type=float, default=1.5)
    parser.add_argument("--settle", type=float, default=2.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--workers", type=int, default=6,
                        help="Số luồng gửi đồng thời cho Bit-flip/Payload mutation")
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

    for name in ("timeout", "probe_timeout", "settle", "delay",
                 "confirm_timeout"):
        if not math.isfinite(getattr(args, name)):
            parser.error(f"{name} must be finite")

    if (
        args.timeout <= 0
        or args.probe_timeout <= 0
        or args.settle < 0
        or args.delay < 0
        or args.confirm_timeout <= 0
    ):
        parser.error(
            "timeouts must be > 0; settle/delay must be >= 0"
        )

    if args.miner_port is not None and args.miner_port not in args.ports:
        parser.error("--miner-port must be included in --ports")
    if args.workers < 1:
        parser.error("--workers must be >= 1")

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
            f"\n[RESULT] ERROR: {error_text(exc)}",
            file=sys.stderr,
        )
        sys.exit(2)
