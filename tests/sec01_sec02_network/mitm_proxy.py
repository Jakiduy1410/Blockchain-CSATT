import argparse
import select
import socket
import threading


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ValueError("EOF before complete ClientHello")
        data.extend(part)
    return bytes(data)


def group_offsets(hello):
    def number(pos):
        if pos + 2 > len(hello):
            raise ValueError("Truncated TLS field")
        return int.from_bytes(hello[pos:pos + 2], "big")

    p = 38
    p += 1 + hello[p]
    p += 2 + number(p)
    p += 1 + hello[p]
    end = p + 2 + number(p)
    p += 2
    if end != len(hello):
        raise ValueError("Invalid extensions length")

    offsets, shares, seen = [], [], set()
    while p < end:
        kind, size = number(p), number(p + 2)
        p += 4
        stop = p + size
        if stop > end or kind in seen:
            raise ValueError("Invalid or duplicate extension")
        seen.add(kind)

        if kind in (10, 51):
            q = p + 2
            if size < 2 or q + number(p) != stop:
                raise ValueError("Invalid group/share vector")
            while q < stop:
                if q + (4 if kind == 51 else 2) > stop:
                    raise ValueError("Truncated group/share")
                group = number(q)
                if group == 0x11EC:
                    offsets.append(q)
                q += 2
                if kind == 51:
                    length = number(q)
                    shares.append((group, length))
                    q += 2 + length
                    if not length or q > stop:
                        raise ValueError("Invalid key share length")
        p = stop
    return offsets, shares


def client_hello(sock):
    wire, handshake, positions = bytearray(), bytearray(), []
    for _ in range(128):
        header = exact(sock, 5)
        size = int.from_bytes(header[3:5], "big")
        if header[0] != 22 or header[1] != 3 or not 0 < size <= 16384:
            raise ValueError("Invalid initial handshake record")
        if len(wire) + 5 + size > 131072:
            raise ValueError("ClientHello too large")

        start = len(wire) + 5
        body = exact(sock, size)
        wire.extend(header + body)
        handshake.extend(body)
        positions.extend(range(start, start + size))

        if len(handshake) >= 4:
            total = 4 + int.from_bytes(handshake[1:4], "big")
            if handshake[0] != 1 or total > 65536:
                raise ValueError("Invalid ClientHello header")
            if len(handshake) >= total:
                offsets, shares = group_offsets(bytes(handshake[:total]))
                return wire, positions, offsets, shares
    raise ValueError("Too many fragmented records")


def handle(client, passthrough):
    try:
        with client, socket.create_connection(
            ("127.0.0.1", 6000), timeout=8
        ) as upstream:
            client.settimeout(8)
            wire, positions, offsets, shares = client_hello(client)

            print(
                f"TCP client={client.getpeername()} "
                f"proxy_upstream={upstream.getsockname()} "
                "node=127.0.0.1:6000",
                flush=True
            )
            print(
                f"BEFORE key_shares={[(hex(g), n) for g, n in shares]}",
                flush=True
            )

            if passthrough:
                print("Forward unchanged: tamper=False", flush=True)
            else:
                if len(offsets) != 2 or (0x11EC, 1216) not in shares:
                    raise ValueError(
                        "Expected hybrid in supported_groups and key_share"
                    )
                for offset in offsets:
                    wire[positions[offset]] = 0
                    wire[positions[offset + 1]] = 0
                print(
                    "AFTER: 0x11ec -> 0x0000 in two group fields; "
                    "key material unchanged",
                    flush=True
                )

            upstream.sendall(wire)
            client.settimeout(None)
            upstream.settimeout(None)

            while True:
                ready, _, _ = select.select([client, upstream], [], [], 30)
                if not ready:
                    return
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    target = upstream if source is client else client
                    target.sendall(data)
    except Exception as exc:
        print(f"Proxy connection ended: {exc}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pass-through", action="store_true")
    args = parser.parse_args()

    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 6500))
        listener.listen(10)
        mode = "PASS_THROUGH" if args.pass_through else "HYBRID_GROUP_TAMPERING"
        print(f"Listening :6500 -> :6000 | {mode}", flush=True)
        try:
            while True:
                client, _ = listener.accept()
                threading.Thread(
                    target=handle,
                    args=(client, args.pass_through),
                    daemon=True
                ).start()
        except KeyboardInterrupt:
            pass
