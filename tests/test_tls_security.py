"""Protocol parsing and real loopback controls. No synthetic success events."""
import importlib.util
import socket
import ssl
import threading
import time
import unittest
from pathlib import Path

from blockchain.network.tls_inspect import HelloError, parse_client_hello, read_client_hello
from blockchain.network.tls_helper import TLSManager, connection_evidence
from websockets.sync.client import connect


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / 'security' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


synthetic = load_script('send_pqc_handshake')
proxy = load_script('mitm_proxy')


class FragmentedSocket:
    def __init__(self, data):
        self.data = data

    def recv(self, size):
        part, self.data = self.data[:min(size, 7)], self.data[min(size, 7):]
        return part


class TestHelloParser(unittest.TestCase):
    def test_synthetic_extensions_and_versions(self):
        packet = synthetic.build_client_hello()
        info = parse_client_hello(packet[5:])
        self.assertEqual(info['groups'], [0x11ec, 29, 23])
        self.assertEqual(info['shares'], [(0x11ec, 1216)])
        self.assertEqual(info['versions'], [0x0304])
        self.assertEqual(packet[1:3], b'\x03\x01')
        self.assertEqual(packet[9:11], b'\x03\x03')

    def test_tamper_only_group_fields_across_records(self):
        message = bytearray(synthetic.build_client_hello()[5:])
        info = parse_client_hello(message)
        # Plant the same bytes inside key material. They must remain untouched.
        payload = info['group_offsets'][-1] + 4
        message[payload:payload + 2] = b'\x11\xec'
        split = info['group_offsets'][0] + 1
        wire = b''.join(b'\x16\x03\x01' + len(part).to_bytes(2, 'big') + part
                        for part in (message[:split], message[split:]))
        original, parsed, positions = read_client_hello(FragmentedSocket(wire))
        modified = proxy.tamper_client_hello(original, parsed, positions)
        changed = {i for i, (a, b) in enumerate(zip(original, modified)) if a != b}
        expected = {positions[o + i] for o in parsed['group_offsets'] for i in (0, 1)}
        self.assertEqual(changed, expected)
        self.assertEqual(modified[positions[payload]:positions[payload] + 2], b'\x11\xec')
        _, after, _ = read_client_hello(FragmentedSocket(modified))
        self.assertEqual(after['groups'], [0, 29, 23])
        self.assertEqual(after['shares'], [(0, 1216)])

    def test_malformed_lengths_and_truncation(self):
        packet = synthetic.build_client_hello()
        for length in (0, 4, 12, 100, len(packet) - 1):
            with self.subTest(length=length), self.assertRaises(HelloError):
                read_client_hello(FragmentedSocket(packet[:length]))
        with self.assertRaises(HelloError):
            parse_client_hello(packet[5:] + b'\x00')

    def test_pqc_policy_cannot_accept_classical_context(self):
        server = TLSManager.create_server_ssl_context(False)
        client = TLSManager.create_client_ssl_context(False)
        server.require_pqc = True
        with self.assertRaises(RuntimeError):
            TLSManager.verify_policy(server, client)


class TestTLSControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            TLSManager.verify_policy(TLSManager.create_server_ssl_context(True),
                                     TLSManager.create_client_ssl_context(True))
        except (RuntimeError, ssl.SSLError) as exc:
            raise unittest.SkipTest(f'Real hybrid unavailable; set OPENSSL_CONF before Python: {exc}')
        from blockchain.config import NodeConfig
        from blockchain.server import create_app
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            cls.port = reservation.getsockname()[1]
        config = NodeConfig()
        config.port = cls.port - 1000
        cls.app, cls.ledger, cls.network, cls.miner = create_app(config)
        cls.ctx = TLSManager.create_client_ssl_context(True)

    @classmethod
    def tearDownClass(cls):
        cls.network.stop()

    def setUp(self):
        with self.ledger.audit.lock:
            self.ledger.audit.logs.clear()

    def connect(self, port=None, ctx=None):
        return connect(f'wss://127.0.0.1:{port or self.port}', ssl=ctx or self.ctx,
                       open_timeout=5, close_timeout=1)

    def critical_event(self):
        for _ in range(40):
            logs = self.app.test_client().get('/audit/logs').get_json()['logs']
            matches = [entry for entry in logs if entry['status'] == 'CRITICAL']
            if matches:
                self.assertEqual(matches[0]['details']['action'], 'DROP_CONNECTION')
                self.assertEqual(matches[0]['details']['defense'], 'PQC_REQUIRED')
                return matches[0]
            time.sleep(.025)
        self.fail('Node did not record a real policy rejection')

    def proxy_port(self, tamper):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        def run():
            with listener:
                client, _ = listener.accept()
                proxy.handle_conn(client, self.port, tamper)
        threading.Thread(target=run, daemon=True).start()
        return port

    def test_normal_and_bidirectional_proxy_control(self):
        for port in (self.port, self.proxy_port(False)):
            with self.connect(port) as ws:
                self.assertEqual(ws.response.status_code, 101)
                self.assertEqual(connection_evidence(ws)['group_id'], '0x11ec')
                self.assertTrue(ws.ping(b'normal-control').wait(2))
        self.assertFalse(any(log['status'] == 'CRITICAL' for log in self.ledger.audit.get_logs()))

    def test_real_hybrid_tampered_proxy_rejected(self):
        with self.assertRaises((ssl.SSLError, OSError)):
            self.connect(self.proxy_port(True))
        event = self.critical_event()
        self.assertEqual(event['details']['offered_groups'], ['0x0'])

    def test_classical_only_rejected(self):
        with self.assertRaises((ssl.SSLError, OSError)):
            self.connect(ctx=TLSManager.create_client_ssl_context(False))
        self.assertEqual(self.critical_event()['details']['reason'], 'HYBRID_PQC_MISSING_OR_TAMPERED')

    def test_malformed_hello_rejected(self):
        packet = bytearray(synthetic.build_client_hello())
        # Invalid supported_groups vector, keeping the record length intact.
        offset = parse_client_hello(packet[5:])['group_offsets'][0] + 5 - 2
        packet[offset:offset + 2] = b'\xff\xff'
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as sock:
            sock.sendall(packet)
            response = sock.recv(4096)
            self.assertTrue(not response or response[0] == 21)
        self.assertEqual(self.critical_event()['details']['reason'], 'MALFORMED_CLIENT_HELLO')

    def test_external_alert_cannot_forge_critical(self):
        response = self.app.test_client().post('/api/audit/alert', json={
            'title': 'PQC defense success', 'status': 'CRITICAL'})
        self.assertEqual(response.status_code, 202)
        event = self.ledger.audit.get_logs()[0]
        self.assertEqual(event['status'], 'WARNING')
        self.assertEqual(event['details']['source'], 'HTTP_REPORT_UNVERIFIED')

    def test_dashboard_and_blockchain_routes(self):
        client = self.app.test_client()
        for url in ('/', '/status', '/accounts/balance', '/chain', '/audit/logs'):
            self.assertEqual(client.get(url).status_code, 200)
        self.assertEqual(client.get('/status').get_json()['tls_policy'], 'PQC_REQUIRED')
        self.assertEqual(client.get('/mine').status_code, 200)
        self.assertGreaterEqual(client.get('/chain').get_json()['length'], 2)
        illustration = client.get('/packet/inspect').get_json()
        self.assertEqual(illustration['evidence_type'], 'SYNTHETIC_ILLUSTRATION_NOT_NETWORK_CAPTURE')


if __name__ == '__main__':
    unittest.main()
