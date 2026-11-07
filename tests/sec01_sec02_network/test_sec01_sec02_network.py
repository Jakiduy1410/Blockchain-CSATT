"""
Unit & Integration Tests for SEC-01 & SEC-02 Network & TLS Security
Tests MitM byte tampering, PQC downgrade prevention, audit alert dispatching, and pcap integrity.
"""

import os
import unittest
from pathlib import Path
from flask import Flask

from blockchain.api.routes import create_api_blueprint
from blockchain.core.ledger import BlockchainLedger
from blockchain.consensus.miner import Miner
from blockchain.network.p2p import P2PNetwork
from tests.sec01_sec02_network.mitm_proxy import tamper_and_strip_pqc


class TestSec01Sec02Network(unittest.TestCase):
    def setUp(self):
        self.base_dir = Path(__file__).resolve().parent.parent.parent
        self.ledger = BlockchainLedger()
        from unittest.mock import MagicMock
        mock_network = MagicMock()
        mock_miner = MagicMock()

        self.app = Flask(__name__)
        self.app.register_blueprint(create_api_blueprint(self.ledger, mock_network, mock_miner, port=5000))
        self.client = self.app.test_client()

    def test_tamper_and_strip_pqc(self):
        """Test MitM proxy PQC stripping logic on TLS Client Hello records."""
        # Simulated TLS 1.3 Client Hello header: 0x16 (Handshake), 0x03 0x01, len=10, 0x01 (Client Hello)
        mock_client_hello = bytearray(b'\x16\x03\x01\x00\x0a\x01\x00\x00\x06\x00')
        # Append PQC extension group id 0x11ec
        mock_client_hello.extend(b'\x11\xec\x00\x1d')

        tampered = tamper_and_strip_pqc(bytes(mock_client_hello))
        # Verify 0x11ec was replaced by 0x0000
        self.assertNotIn(b'\x11\xec', tampered)
        self.assertIn(b'\x00\x00\x00\x1d', tampered)

        # Test non-handshake data is left unchanged
        plain_data = b'hello world random packet'
        self.assertEqual(tamper_and_strip_pqc(plain_data), plain_data)

    def test_audit_alert_endpoint(self):
        """Test that the /api/audit/alert endpoint logs CRITICAL downgrade alerts."""
        payload = {
            "category": "P2P",
            "title": "CANH BAO AN NINH: P2P TLS Downgrade Attack Detected!",
            "details": {
                "attacker": "127.0.0.1:6500",
                "stripped_extension": "X25519MLKEM768 (0x11ec)",
                "action": "DROP_CONNECTION"
            },
            "status": "CRITICAL"
        }
        res = self.client.post('/api/audit/alert', json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get('status'), 'SUCCESS')

        # Check in audit logs
        logs = self.ledger.audit.get_logs(limit=5)
        self.assertTrue(any(log['status'] == 'CRITICAL' and 'Downgrade' in log['title'] for log in logs))

    def test_pcap_capture_file_validity(self):
        """Verify pqc_p2p_capture.pcap exists and has a valid pcap/pcapng header."""
        pcap_path = self.base_dir / "benchmarks" / "results" / "sec01_hndl_mitm" / "pqc_p2p_capture.pcap"
        self.assertTrue(pcap_path.is_file(), "pqc_p2p_capture.pcap must exist in benchmarks/results/sec01_hndl_mitm")
        with open(pcap_path, "rb") as f:
            header = f.read(4)
        # Standard pcap magic (0xa1b2c3d4 / 0xd4c3b2a1) or pcapng magic (0x0a0d0d0a)
        valid_magics = [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\n\r\r\n', b'\r\n\n\r']
        self.assertIn(header, valid_magics, "File must have valid pcap/pcapng magic header")


if __name__ == "__main__":
    unittest.main()
