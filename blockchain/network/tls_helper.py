"""
TLS Helper: Tạo và quản lý chứng chỉ SSL tự ký hỗ trợ TLS 1.3 / ECDHE
"""

import datetime
import os
import ssl
import tempfile
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


class TLSManager:
    _instance = None
    _cert_path = None
    _key_path = None

    @classmethod
    def get_or_create_cert(cls) -> Tuple[str, str]:
        """Tạo hoặc lấy chứng chỉ ECDSA/ECDHE tạm thời dùng cho giao thức P2P WSS"""
        if cls._cert_path and cls._key_path and os.path.exists(cls._cert_path) and os.path.exists(cls._key_path):
            return cls._cert_path, cls._key_path

        # Sinh cặp khóa ECDSA secp256r1
        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'Blockchain P2P Node'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Blockchain-CSATT P2P Mesh'),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).sign(key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        cert_fd, cert_path = tempfile.mkstemp(prefix='p2p_cert_', suffix='.crt')
        key_fd, key_path = tempfile.mkstemp(prefix='p2p_key_', suffix='.key')

        with os.fdopen(cert_fd, 'wb') as f:
            f.write(cert_pem)
        with os.fdopen(key_fd, 'wb') as f:
            f.write(key_pem)

        cls._cert_path = cert_path
        cls._key_path = key_path
        return cert_path, key_path

    @classmethod
    def create_server_ssl_context(cls) -> ssl.SSLContext:
        """Tạo SSL Context cho WebSocket Server bọc TLS 1.3 / ECDHE"""
        cert_path, key_path = cls.get_or_create_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        keylog = os.environ.get("SSLKEYLOGFILE")
        if keylog:
            try:
                ctx.keylog_filename = keylog
            except Exception:
                pass
        try:
            ctx.set_ecdh_curve('prime256v1')
        except Exception:
            pass
        return ctx
    @classmethod
    def create_client_ssl_context(cls) -> ssl.SSLContext:
        """Tạo SSL Context cho WebSocket Client bọc TLS 1.3 / ECDHE"""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        keylog = os.environ.get("SSLKEYLOGFILE")
        if keylog:
            try:
                ctx.keylog_filename = keylog
            except Exception:
                pass
        try:
            ctx.set_ecdh_curve('prime256v1')
        except Exception:
            pass
        return ctx
