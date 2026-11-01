#!/usr/bin/env python3
"""
SEC-03: HTTP / HTTPS / WebSocket fuzzing.

Examples:
    python3 attack_sec03.py --transport http
    python3 attack_sec03.py --transport http --assume-replay-blocked
    python3 attack_sec03.py --transport https --insecure
    python3 attack_sec03.py --transport wss --ws-path /ws --insecure

Normal completion:
    334 bit-flipping + 333 payload mutation
    + 1 replay baseline + 332 replay attempts = 1,000 transaction sends.

Pre-check traffic is additional diagnostic traffic:
    HTTP:  TCP -> HTTP health GET
    HTTPS: TCP -> TLS 1.3 -> HTTPS health GET
    WSS:   TCP -> TLS 1.3 -> WebSocket handshake -> Ping/Pong

Dependencies:
    requests
    websockets>=15 only for WSS
    The project's Flask and cryptographic dependencies.

--assume-replay-blocked:
    Preserves the earlier assumption-based replay classification.
    Connection failures remain Unknown.
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import math
import random
import re
import socket
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

HTTP_TRANSPORTS = {"http", "https"}
TLS_TRANSPORTS = {"https", "wss"}

ACCEPTED = {"accepted", "success", "created", "ok"}
REJECTED = {"rejected", "invalid", "blocked", "denied"}
DUPLICATE = {"duplicate", "ignored", "skipped", "already_processed"}

NETWORK_ERRORS = (
    OSError,
    TimeoutError,
    requests.exceptions.RequestException,
)


def json_text(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def valid_hex(value: Any, name: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) % 2
        or not re.fullmatch(r"[0-9a-fA-F]+", value)
    ):
        raise ValueError(f"{name}: invalid hex")

    return bytes.fromhex(value)


def exception_chain(exc: BaseException) -> str:
    """Include wrapped urllib3, socket, and SSL causes."""
    output = []
    visited = set()

    def visit(error: BaseException) -> None:
        if id(error) in visited:
            return

        visited.add(id(error))
        output.append(f"{type(error).__name__}: {error}")

        cause = error.__cause__ or error.__context__
        if isinstance(cause, BaseException):
            visit(cause)

        reason = getattr(error, "reason", None)
        if isinstance(reason, BaseException):
            visit(reason)

        for argument in error.args:
            if isinstance(argument, BaseException):
                visit(argument)

    visit(exc)
    return " -> ".join(output)


def normalize(value: str) -> str:
    value = value.casefold().replace("đ", "d").replace("_", " ")

    return "".join(
        char
        for char in unicodedata.normalize("NFD", value)
        if unicodedata.category(char) != "Mn"
    )


def response_code(body: Any) -> int | None:
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


def has_duplicate_evidence(body: Any) -> bool:
    if not isinstance(body, dict):
        return False

    if any(
        body.get(key) is True
        for key in ("duplicate", "ignored", "skipped", "replay_detected")
    ):
        return True

    if str(body.get("status", "")).lower() in DUPLICATE:
        return True

    for key in ("code", "error_code", "message", "reason"):
        value = body.get(key)
        if not isinstance(value, str):
            continue

        text = normalize(value)

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


def has_application_reply(body: Any) -> bool:
    if not isinstance(body, dict):
        return False

    return (
        response_code(body) is not None
        or isinstance(body.get("accepted"), bool)
        or isinstance(body.get("success"), bool)
        or str(body.get("status", "")).lower()
        in ACCEPTED | REJECTED | DUPLICATE
        or has_duplicate_evidence(body)
    )


class ProjectClient:
    """Call project signing endpoints in RAM, without network requests."""

    def __init__(self, root: Path, client_file: Path | None):
        self.root = root

        paths = (
            [client_file.resolve()]
            if client_file
            else [
                root / "blockchain_client" / "blockchain_client.py",
                root / "blockchain_client.py",
            ]
        )

        source = next((path for path in paths if path.is_file()), None)
        if source is None:
            raise RuntimeError("Cannot find blockchain_client.py")

        sys.path.insert(0, str(root))
        sys.path.insert(0, str(source.parent))

        spec = importlib.util.spec_from_file_location("sec03_client", source)
        if spec is None or spec.loader is None:
            raise RuntimeError("Cannot import project client")

        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)

        app = getattr(module, "app", None)
        if not callable(getattr(app, "test_client", None)):
            raise RuntimeError("Client must expose a Flask app")

        self.client = app.test_client()
        self.algorithm = str(getattr(module, "SIG_ALG", "project-defined"))

    def wallet(self) -> dict:
        response = self.client.get("/wallet/new")
        data = response.get_json(silent=True)

        if response.status_code != 200 or not isinstance(data, dict):
            raise RuntimeError("Project /wallet/new failed")

        valid_hex(data.get("public_key"), "public_key")
        valid_hex(data.get("private_key"), "private_key")
        return data

    def sign(self, wallet: dict, recipient: str, amount: int) -> dict:
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
        valid_hex(signature, "signature")

        if tx.get("sender_address") != wallet["public_key"]:
            raise RuntimeError("Unexpected signed sender")

        if tx.get("recipient_address") != recipient:
            raise RuntimeError("Unexpected signed recipient")

        if str(tx.get("amount", tx.get("value"))) != str(amount):
            raise RuntimeError("Unexpected signed amount")

        tx.pop("value", None)
        tx["amount"] = amount
        tx["signature"] = signature
        tx.setdefault("nonce", nonce)

        json_text(tx)
        return tx

    def fixtures(self, name: str | None) -> list[dict]:
        recipient = self.wallet()["public_key"]
        wallets = {}

        for path in (
            self.root / "configs" / "wallets.json",
            self.root / "wallets.json",
        ):
            if path.is_file():
                wallets = json.loads(path.read_text(encoding="utf-8"))
                break

        if not isinstance(wallets, dict):
            raise ValueError("wallets.json must contain an object")

        if name and name not in wallets:
            raise ValueError(f"Wallet {name!r} not found")

        sender = None
        baseline = None
        selected = None

        for candidate in ([name] if name else list(wallets)):
            wallet = wallets[candidate]

            try:
                balance = float(wallet.get("initial_balance", 0))

                if not math.isfinite(balance) or balance < 1:
                    continue

                if len(valid_hex(wallet["public_key"], "public_key")) != len(
                    valid_hex(recipient, "recipient")
                ):
                    continue

                signed = self.sign(wallet, recipient, 1)

            except (
                ValueError,
                KeyError,
                TypeError,
                AttributeError,
                RuntimeError,
            ):
                continue

            sender = wallet
            baseline = signed
            selected = candidate
            break

        if sender is None:
            raise RuntimeError(
                "No compatible funded sample wallet. Configure a funded test "
                "wallet in configs/wallets.json, or select one with --wallet."
            )

        print(f"[SIGNER] {self.algorithm}; wallet={selected}")
        print("[FIXTURES] Generating 668 signed transactions...")

        fixtures = [
            self.sign(sender, recipient, amount)
            for amount in range(2, 669)
        ]
        fixtures.append(baseline)

        return fixtures


class TLSAdapter(HTTPAdapter):
    """Used only for HTTPS, never for plain HTTP."""

    def __init__(self, context: ssl.SSLContext):
        self.context = context
        super().__init__(max_retries=0)

    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        kwargs["ssl_context"] = self.context
        return super().init_poolmanager(
            connections,
            maxsize,
            block=block,
            **kwargs,
        )


@dataclass
class Observation:
    http_status: int | None
    application_code: int | None
    body: Any
    error: str | None
    elapsed_ms: float


class Transport:
    def __init__(self, args):
        self.args = args
        self.context = None
        self.ws_connect = None
        self.ws_errors = ()

        # FIX: plain HTTP requires no SSL context or TLS handshake.
        if args.transport in TLS_TRANSPORTS:
            self.context = ssl.create_default_context(cafile=args.ca_file)
            self.context.minimum_version = ssl.TLSVersion.TLSv1_3
            self.context.maximum_version = ssl.TLSVersion.TLSv1_3

            if args.insecure:
                self.context.check_hostname = False
                self.context.verify_mode = ssl.CERT_NONE
                print("[TLS] Certificate verification disabled (--insecure).")

            if args.client_cert:
                self.context.load_cert_chain(
                    args.client_cert,
                    keyfile=args.client_key,
                )
        else:
            print("[TRANSPORT] Plain HTTP; TLS is disabled.")

            if (
                args.insecure
                or args.ca_file
                or args.client_cert
                or args.client_key
            ):
                print("[INFO] TLS options are ignored for --transport http.")

        self.session = requests.Session()
        self.session.trust_env = False

        # FIX: explicitly configure a standard adapter for HTTP.
        self.session.mount("http://", HTTPAdapter(max_retries=0))

        if args.transport == "https":
            self.session.mount("https://", TLSAdapter(self.context))
            self.session.verify = (
                False if args.insecure else args.ca_file or True
            )

            if args.client_cert:
                self.session.cert = (
                    (args.client_cert, args.client_key)
                    if args.client_key
                    else args.client_cert
                )

        if args.transport == "wss":
            try:
                from websockets.sync.client import connect
                from websockets.exceptions import WebSocketException
            except ImportError as exc:
                raise RuntimeError(
                    'Install WebSocket support: pip install "websockets>=15"'
                ) from exc

            self.ws_connect = connect
            self.ws_errors = (WebSocketException,)

    def url(self, port: int, path: str) -> str:
        return f"{self.args.transport}://{self.args.host}:{port}{path}"

    def open_ws(self, port: int):
        return self.ws_connect(
            self.url(port, self.args.ws_path),
            ssl=self.context,
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

    def precheck(self) -> None:
        failures = []

        if self.args.transport == "http":
            print("\n[PRE-CHECK] TCP -> HTTP health endpoint")
        else:
            print("\n[PRE-CHECK] TCP -> TLS 1.3 -> application transport")

        for port in self.args.ports:
            stage = "TCP"
            connection_detail = "plain HTTP; no TLS"

            try:
                with socket.create_connection(
                    (self.args.host, port),
                    timeout=self.args.timeout,
                ) as raw:

                    # FIX: TLS wrapping happens only for HTTPS/WSS.
                    if self.args.transport in TLS_TRANSPORTS:
                        stage = "TLS"

                        with self.context.wrap_socket(
                            raw,
                            server_hostname=self.args.host,
                        ) as tls:
                            version = tls.version()
                            cipher = tls.cipher()[0]
                            connection_detail = f"{version} | {cipher}"

                stage = self.args.transport.upper()

                # FIX: HTTP and HTTPS share the REST health-check branch.
                if self.args.transport in HTTP_TRANSPORTS:
                    response = self.session.get(
                        self.url(port, self.args.health_path),
                        timeout=self.args.timeout,
                        allow_redirects=False,
                    )

                    if not 200 <= response.status_code < 300:
                        raise RuntimeError(
                            f"Health endpoint returned HTTP "
                            f"{response.status_code}; check --health-path"
                        )

                    detail = f"health HTTP {response.status_code}"

                else:
                    with self.open_ws(port) as ws:
                        pong = ws.ping()

                        if not pong.wait(self.args.timeout):
                            raise TimeoutError("WebSocket Pong timeout")

                    detail = "WebSocket handshake + Pong OK"

                print(
                    f"[OK] {self.args.host}:{port} | "
                    f"{connection_detail} | {detail}",
                    flush=True,
                )

            except Exception as exc:
                error = exception_chain(exc)
                failures.append((port, stage, error))

                print(
                    f"[FAIL] {self.args.host}:{port} | "
                    f"stage={stage} | {error}",
                    flush=True,
                )

        if failures:
            print(
                "\nKiểm tra trên máy chạy Node:\n"
                "  ss -ltnp | grep -E ':(5000|5001|5002|5003|5004|5005)\\b'\n"
                "  - Xác nhận đúng port API; port P2P có thể khác port API.\n"
                "  - ConnectionRefusedError: kiểm tra Node, listener và port mapping.\n"
                "  - HTTP 404: kiểm tra --health-path; mặc định là /status.\n"
                "  - Nếu chạy trong container/VM, 127.0.0.1 là chính container/VM đó."
            )

            if self.args.transport == "http":
                print(
                    "  - Server HTTP thường: dùng --transport http.\n"
                    f"  curl -v http://{self.args.host}:"
                    f"{self.args.ports[0]}{self.args.health_path}"
                )
            else:
                print(
                    "  - Kiểm tra Node đã bật TLS 1.3.\n"
                    "  - Kiểm tra CA/SAN của chứng chỉ.\n"
                    "  - Nếu dùng mTLS: cung cấp --client-cert và --client-key.\n"
                    "  - WRONG_VERSION_NUMBER: port có thể đang phục vụ HTTP thường.\n"
                    "  - InvalidHandshake/HTTP 404: kiểm tra --ws-path."
                )

            raise RuntimeError(
                "Pre-check failed; no transaction tests were sent"
            )

    def wire(self, transaction: dict) -> str:
        payload: Any = transaction

        if (
            self.args.transport == "wss"
            and self.args.ws_payload_key
        ):
            payload = {
                self.args.ws_payload_key: transaction,
            }

            if self.args.ws_type:
                payload["type"] = self.args.ws_type

        return json_text(payload)

    def send(self, port: int, wire: str) -> Observation:
        started = time.monotonic()
        http_status = None
        body = None
        error = None

        try:
            # FIX: plain HTTP uses requests.post with an http:// URL.
            if self.args.transport in HTTP_TRANSPORTS:
                response = self.session.post(
                    self.url(port, self.args.tx_path),
                    data=wire.encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    timeout=self.args.timeout,
                    allow_redirects=False,
                )
                http_status = response.status_code

                try:
                    body = response.json()
                except ValueError:
                    body = {
                        "non_json_response": response.text[:2000],
                    }

            else:
                # One transaction per connection. No automatic resend.
                with self.open_ws(port) as ws:
                    ws.send(wire)
                    deadline = time.monotonic() + self.args.timeout

                    while True:
                        remaining = deadline - time.monotonic()

                        if remaining <= 0:
                            raise TimeoutError(
                                "No matching transaction JSON acknowledgement"
                            )

                        raw_reply = ws.recv(timeout=remaining)

                        try:
                            candidate = json.loads(raw_reply)
                        except (ValueError, UnicodeError):
                            continue

                        if (
                            self.args.ws_reply_type
                            and (
                                not isinstance(candidate, dict)
                                or candidate.get("type")
                                != self.args.ws_reply_type
                            )
                        ):
                            continue

                        if has_application_reply(candidate):
                            body = candidate
                            break

        except NETWORK_ERRORS + self.ws_errors as exc:
            error = exception_chain(exc)

            print(
                f"[NETWORK ERROR] {self.args.host}:{port} | {error}",
                flush=True,
            )

        return Observation(
            http_status=http_status,
            application_code=response_code(body),
            body=body,
            error=error,
            elapsed_ms=round(
                (time.monotonic() - started) * 1000,
                3,
            ),
        )

    def close(self):
        self.session.close()


def accepted(obs: Observation) -> bool:
    if obs.error:
        return False

    body = obs.body if isinstance(obs.body, dict) else {}
    status = str(body.get("status", "")).lower()

    if (
        body.get("accepted") is False
        or body.get("success") is False
        or bool(body.get("error"))
        or status in REJECTED | DUPLICATE
        or has_duplicate_evidence(body)
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
    if obs.error:
        return "unknown", "transport_error", "transport"

    if kind == REPLAY:
        if not baseline_ok:
            return "unknown", "baseline_not_established", "baseline"

        if assume_replay:
            return "blocked", "replay_override", "assumption"

        if has_duplicate_evidence(obs.body):
            return "blocked", "explicit_duplicate_response", "application"

    code = (
        obs.http_status
        if obs.http_status is not None
        else obs.application_code
    )

    body = obs.body if isinstance(obs.body, dict) else {}
    status = str(body.get("status", "")).lower()

    if kind != REPLAY and (
        code == 406
        or status in REJECTED
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
    rows = []
    total = Stats()

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
            "requests",
            "blocked",
            "accepted",
            "unknown",
            "baseline_ok",
            "baseline_failed",
            "assumed",
        ):
            setattr(
                total,
                key,
                getattr(total, key) + getattr(item, key),
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
        "Scenario",
        "Sent",
        "Blocked",
        "Accepted",
        "Unknown",
        "Baseline OK/Fail",
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

    print(f"\n[BENCHMARK] {algorithm}: client-observed transport latency")
    print(
        "Includes connection establishment where needed "
        "and application response time."
    )

    for name, item in stats.items():
        average = (
            f"{math.fsum(item.times) / len(item.times):.2f} ms"
            if item.times
            else "N/A"
        )
        print(
            f"  {name}: {average}; "
            f"blocked samples={len(item.times)}"
        )

    if total.assumed:
        print(
            f"ASSUMED replay blocks: {total.assumed}; "
            "ledger was not verified."
        )

    passed = (
        total.requests == 1000
        and total.blocked == 999
        and total.baseline_ok == 1
        and total.unknown == 0
        and total.accepted == 0
        and total.baseline_failed == 0
    )

    if passed:
        if total.assumed:
            print("PASS under configured replay assumption:")

        print(
            "PASS: 999/999 attack attempts blocked (100%); "
            "baseline accepted."
        )
        return 0

    print("NOT PASS: review transport/application responses in JSONL.")
    return 1 if total.accepted else 2


def show_sample(path):
    sample = None
    count = 0
    rng = random.SystemRandom()

    with path.open(encoding="utf-8") as handle:
        for line in handle:
            try:
                item = json.loads(line)
            except ValueError:
                continue

            if not isinstance(item, dict):
                continue

            if item.get("result") == "blocked":
                count += 1
                if rng.randrange(count) == 0:
                    sample = item

    if sample:
        print("\n[LOG SAMPLE] Random record classified as blocked:")
        print(json.dumps(sample, ensure_ascii=False, indent=2))


def run(args):
    transport = Transport(args)

    try:
        # Fail before signing or sending any transaction.
        transport.precheck()

        project = ProjectClient(
            args.project_root.resolve(),
            args.client_file,
        )
        fixtures = project.fixtures(args.wallet)

        rng = random.Random(args.seed)
        cases = []

        for tx in fixtures[:334]:
            altered = copy.deepcopy(tx)
            signature = bytearray.fromhex(tx["signature"])

            for bit in rng.sample(
                range(len(signature) * 8),
                rng.randint(1, 4),
            ):
                signature[bit // 8] ^= 1 << (bit % 8)

            altered["signature"] = signature.hex()
            cases.append((BIT, transport.wire(altered), False))

        for index, tx in enumerate(fixtures[334:667]):
            altered = copy.deepcopy(tx)

            if index % 2 == 0:
                altered["amount"] *= 100
            else:
                address = list(altered["recipient_address"])
                position = rng.randrange(len(address))
                address[position] = format(
                    int(address[position], 16) ^ 1,
                    "x",
                )
                altered["recipient_address"] = "".join(address)

            cases.append((MUTATION, transport.wire(altered), False))

        rng.shuffle(cases)

        replay_wire = transport.wire(fixtures[-1])
        cases.append((REPLAY, replay_wire, True))
        cases.extend(
            (REPLAY, replay_wire, False)
            for _ in range(332)
        )

        assert len(cases) == 1000

        stats = {name: Stats() for name in KINDS}
        seen = set()
        baseline_ok = False
        replay_index = 0
        interrupted = False

        args.log.parent.mkdir(parents=True, exist_ok=True)

        try:
            with args.log.open("x", encoding="utf-8") as log:
                for number, (kind, wire, baseline) in enumerate(cases, 1):
                    if kind == REPLAY:
                        port = args.ports[
                            replay_index % len(args.ports)
                        ]
                        replay_index += 1
                    else:
                        port = rng.choice(args.ports)

                    if kind not in seen:
                        seen.add(kind)
                        print(
                            f"\n[TRACE] {kind} -> "
                            f"{args.transport}://{args.host}:{port}",
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

                    setattr(
                        item,
                        result,
                        getattr(item, result) + 1,
                    )

                    if result == "blocked":
                        item.times.append(obs.elapsed_ms)

                        if evidence == "assumption":
                            item.assumed += 1

                    record = {
                        "time_utc": datetime.now(timezone.utc).isoformat(),
                        "request": number,
                        "scenario": kind,
                        "transport": args.transport,
                        "port": port,
                        "baseline": baseline,
                        "result": result,
                        "reason": reason,
                        "evidence_type": evidence,
                        "ledger_verified": False,
                        "http_status": obs.http_status,
                        "application_code": obs.application_code,
                        "elapsed_ms": obs.elapsed_ms,
                        "response": obs.body,
                        "network_error": obs.error,
                    }

                    log.write(json_text(record) + "\n")
                    log.flush()

                    if baseline:
                        print(f"[BASELINE] {result}", flush=True)

                        if not baseline_ok:
                            print(
                                "Stopping replay: baseline was not acknowledged. "
                                "Check the API response or sender balance."
                            )
                            break

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

        code = report(stats, project.algorithm)

        if args.show_sample:
            show_sample(args.log)

        print(f"Log: {args.log.resolve()}")
        return 130 if interrupted else code

    finally:
        transport.close()


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)

    # FIX: add plain HTTP as a valid transport.
    parser.add_argument(
        "--transport",
        choices=("http", "https", "wss"),
        required=True,
    )

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        default=list(range(5000, 5006)),
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path.cwd(),
    )
    parser.add_argument("--client-file", type=Path)
    parser.add_argument("--wallet")

    parser.add_argument("--tx-path", default="/transactions/new")
    parser.add_argument("--health-path", default="/status")
    parser.add_argument("--ws-path", default="/")
    parser.add_argument("--ws-type")
    parser.add_argument("--ws-payload-key")
    parser.add_argument("--ws-reply-type")
    parser.add_argument("--ws-subprotocol")

    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--insecure", action="store_true")
    tls.add_argument("--ca-file")

    parser.add_argument("--client-cert")
    parser.add_argument("--client-key")

    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--settle", type=float, default=2.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--seed", type=int, default=3)

    parser.add_argument(
        "--assume-replay-blocked",
        action="store_true",
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
        parser.error("Invalid port")

    if len(set(args.ports)) != len(args.ports):
        parser.error("Duplicate ports")

    for name in ("timeout", "settle", "delay"):
        if not math.isfinite(getattr(args, name)):
            parser.error(f"--{name} must be finite")

    if args.timeout <= 0 or args.settle < 0 or args.delay < 0:
        parser.error("timeout > 0; settle/delay >= 0")

    for name in ("tx_path", "health_path", "ws_path"):
        if not getattr(args, name).startswith("/"):
            parser.error(
                f"--{name.replace('_', '-')} must start with /"
            )

    if (
        args.transport in TLS_TRANSPORTS
        and args.client_key
        and not args.client_cert
    ):
        parser.error("--client-key requires --client-cert")

    if args.ws_type and not args.ws_payload_key:
        parser.error("--ws-type requires --ws-payload-key")

    if args.ws_payload_key == "type" and args.ws_type:
        parser.error(
            "--ws-payload-key cannot be 'type' when --ws-type is set"
        )

    return args


if __name__ == "__main__":
    try:
        sys.exit(run(parse_args()))
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print(
            f"\n[FATAL] {exception_chain(exc)}",
            file=sys.stderr,
        )
        sys.exit(2)
