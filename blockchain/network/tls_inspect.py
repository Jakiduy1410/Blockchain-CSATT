"""Bounded TLS hello parsing for lab evidence, not a TLS implementation."""

HYBRID_GROUP = 0x11EC
HYBRID_NAME = 'X25519MLKEM768'
MAX_HELLO = 65536


class HelloError(ValueError):
    pass


class Reader:
    def __init__(self, data, start=0, end=None):
        self.data, self.pos = data, start
        self.end = len(data) if end is None else end

    def take(self, size):
        if size < 0 or self.pos + size > self.end:
            raise HelloError('truncated TLS field')
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def number(self, size=2):
        return int.from_bytes(self.take(size), 'big')

    def vector(self, size=2):
        length = self.number(size)
        start = self.pos
        self.take(length)
        return Reader(self.data, start, self.pos)

    def done(self):
        if self.pos != self.end:
            raise HelloError('invalid TLS vector length')


def hello_extensions(message, server=False):
    r = Reader(message)
    if r.number(1) != (2 if server else 1):
        raise HelloError('unexpected handshake type')
    if r.number(3) != len(message) - 4:
        raise HelloError('invalid handshake length')
    r.take(34)  # legacy_version and random, NOT negotiated TLS version
    session = r.vector(1)
    if session.end - session.pos > 32:
        raise HelloError('invalid session id length')
    if server:
        r.take(3)  # selected cipher and compression
    else:
        ciphers = r.vector()
        if ciphers.end == ciphers.pos or (ciphers.end - ciphers.pos) % 2:
            raise HelloError('invalid cipher vector')
        compression = r.vector(1)
        if compression.take(1) != b'\x00':
            raise HelloError('invalid compression')
        compression.done()
    extensions = r.vector()
    r.done()
    result = {}
    while extensions.pos < extensions.end:
        kind = extensions.number()
        if kind in result:
            raise HelloError('duplicate extension')
        result[kind] = extensions.vector()
    return result


def parse_client_hello(message):
    extensions = hello_extensions(message)
    groups, shares, offsets, versions = [], [], [], []
    if 10 in extensions:
        ext = extensions[10]
        vector = ext.vector()
        ext.done()
        while vector.pos < vector.end:
            offset = vector.pos
            group = vector.number()
            groups.append(group)
            if group == HYBRID_GROUP:
                offsets.append(offset)
        if not groups or len(set(groups)) != len(groups):
            raise HelloError('empty or duplicate supported_groups')
    if 51 in extensions:
        ext = extensions[51]
        vector = ext.vector()
        ext.done()
        while vector.pos < vector.end:
            offset = vector.pos
            group = vector.number()
            key = vector.vector()
            length = key.end - key.pos
            if not length or any(g == group for g, _ in shares):
                raise HelloError('empty or duplicate key_share')
            shares.append((group, length))
            if group == HYBRID_GROUP:
                offsets.append(offset)
    if 43 in extensions:
        ext = extensions[43]
        vector = ext.vector(1)
        ext.done()
        while vector.pos < vector.end:
            versions.append(vector.number())
    return {'groups': groups, 'shares': shares, 'group_offsets': offsets,
            'versions': versions}


def parse_server_group(message):
    ext = hello_extensions(message, server=True).get(51)
    if ext is None:
        return None
    group = ext.number()
    # HelloRetryRequest contains only the selected group, not a key share.
    if ext.pos == ext.end:
        return None
    key = ext.vector()
    ext.done()
    if key.pos == key.end:
        raise HelloError('empty server key share')
    return group


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise HelloError('EOF before complete ClientHello')
        data.extend(chunk)
    return bytes(data)


def read_client_hello(sock):
    """Reassemble across TCP reads and TLS records, retaining wire offsets."""
    wire, handshake, positions = bytearray(), bytearray(), []
    for _ in range(128):
        header = recv_exact(sock, 5)
        length = int.from_bytes(header[3:5], 'big')
        if header[0] != 22 or header[1] != 3 or not 0 < length <= 16384:
            raise HelloError('invalid initial handshake record')
        if len(wire) + 5 + length > MAX_HELLO + 1024:
            raise HelloError('ClientHello exceeds lab size limit')
        start = len(wire) + 5
        payload = recv_exact(sock, length)
        wire.extend(header + payload)
        handshake.extend(payload)
        positions.extend(range(start, start + length))
        if len(handshake) >= 4:
            size = 4 + int.from_bytes(handshake[1:4], 'big')
            if size > MAX_HELLO or handshake[0] != 1:
                raise HelloError('invalid ClientHello header')
            if len(handshake) >= size:
                info = parse_client_hello(bytes(handshake[:size]))
                return bytes(wire), info, positions
    raise HelloError('too many fragmented records')
