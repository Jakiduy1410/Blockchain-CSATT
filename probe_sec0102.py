import importlib.util
import os
from pathlib import Path

root = Path.cwd()
assert os.environ.get("OPENSSL_CONF") == str(root / "configs/pqc_openssl.cnf")
import ssl

spec = importlib.util.spec_from_file_location(
    "lab_tls", root / "blockchain/network/tls_helper.py"
)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
TLS = helper.TLSManager


def selected_group(wire):
    messages = bytearray()
    pos = 0
    while pos + 5 <= len(wire):
        size = int.from_bytes(wire[pos + 3:pos + 5], "big")
        if wire[pos] == 22:
            messages.extend(wire[pos + 5:pos + 5 + size])
        pos += 5 + size

    assert messages[0] == 2, "Missing ServerHello"
    end = 4 + int.from_bytes(messages[1:4], "big")
    pos = 38
    pos += 1 + messages[pos] + 3
    size = int.from_bytes(messages[pos:pos + 2], "big")
    pos += 2
    assert pos + size == end

    while pos < end:
        kind = int.from_bytes(messages[pos:pos + 2], "big")
        size = int.from_bytes(messages[pos + 2:pos + 4], "big")
        pos += 4
        if kind == 51:
            assert size > 2, "HelloRetryRequest is not a completed exchange"
            return int.from_bytes(messages[pos:pos + 2], "big")
        pos += size
    raise AssertionError("Missing server key_share")


def probe(curve=None):
    server = TLS.create_server_ssl_context(mode="hybrid")
    client = TLS.create_client_ssl_context(mode="hybrid", verify_peer=False)
    if curve:
        client.set_ecdh_curve(curve)

    ci, co, si, so = (ssl.MemoryBIO() for _ in range(4))
    c = client.wrap_bio(ci, co, server_hostname="localhost")
    s = server.wrap_bio(si, so, server_side=True)
    done = set()
    wire = bytearray()

    for _ in range(100):
        for label, obj in (("client", c), ("server", s)):
            if label in done:
                continue
            try:
                obj.do_handshake()
                done.add(label)
            except ssl.SSLWantReadError:
                pass
            except ssl.SSLError as exc:
                if curve and label == "server" and exc.reason in {
                    "NO_SUITABLE_KEY_SHARE",
                    "NO_SHARED_GROUPS",
                    "NO_SUITABLE_GROUPS",
                }:
                    print(f"PASS {curve}: server rejected ({exc.reason})")
                    return
                raise

        data = co.read()
        if data:
            si.write(data)
        data = so.read()
        if data:
            wire.extend(data)
            ci.write(data)

        if len(done) == 2:
            assert not curve, f"FAIL: classical {curve} was accepted"
            assert c.version() == "TLSv1.3"
            group = selected_group(wire)
            assert group == 0x11EC, f"Wrong group: {group:#06x}"

            c.write(b"probe")
            si.write(co.read())
            assert s.read() == b"probe"
            s.write(b"reply")
            ci.write(so.read())
            assert c.read() == b"reply"

            print("PASS hybrid: TLSv1.3, group=0x11ec, encrypted round trip OK")
            return

    raise AssertionError("Handshake did not finish")


probe()
probe("X25519")
probe("prime256v1")
print("PASS ALL - memory only; no TCP capture created")
