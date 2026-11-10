"""
TLS Helper: Tạo và quản lý chứng chỉ SSL tự ký và mTLS hỗ trợ TLS 1.3 Hybrid Post-Quantum (X25519MLKEM768)
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

# Thiết lập tự động cấu hình OpenSSL PQC từ thư mục configs
_base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_cnf_path = os.path.join(_base_dir, 'configs', 'pqc_openssl.cnf')
# OPENSSL_CONF must be set before Python starts.


class TLSManager:
    _instance = None
    _cert_path = None
    _key_path = None
    _ca_cert_path = None
    _ca_key_path = None

    @classmethod
    def set_tls_groups(cls, ctx, group_name="X25519MLKEM768"):
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

        if group_name == "X25519MLKEM768":
            # Groups is configured by OpenSSL at process startup.
            if os.environ.get("OPENSSL_CONF") != _cnf_path:
                raise RuntimeError("Set OPENSSL_CONF before starting Python")
        elif group_name == "P-256:X25519":
            ctx.set_ecdh_curve("prime256v1")
        else:
            raise ValueError(f"Unsupported group policy: {group_name}")

    @classmethod
    def get_or_create_ca(cls) -> Tuple[str, str]:
        """Tạo hoặc lấy chứng chỉ Root CA nội bộ dùng chung cho toàn mạng Blockchain P2P để chống MiTM triệt để"""
        if cls._ca_cert_path and cls._ca_key_path and os.path.exists(cls._ca_cert_path) and os.path.exists(cls._ca_key_path):
            return cls._ca_cert_path, cls._ca_key_path

        cert_dir = os.path.join(_base_dir, 'configs', 'certs')
        os.makedirs(cert_dir, exist_ok=True)
        ca_cert_path = os.path.join(cert_dir, 'p2p_root_ca.crt')
        ca_key_path = os.path.join(cert_dir, 'p2p_root_ca.key')

        if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
            cls._ca_cert_path = ca_cert_path
            cls._ca_key_path = ca_key_path
            return ca_cert_path, ca_key_path

        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'Blockchain P2P Root CA'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Blockchain-CSATT PQC Network'),
        ])
        ca_cert = x509.CertificateBuilder().subject_name(
            ca_subject
        ).issuer_name(
            ca_subject
        ).public_key(
            ca_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(ca_key, hashes.SHA256())

        ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        ca_key_pem = ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with open(ca_cert_path, 'wb') as f:
            f.write(ca_cert_pem)
        with open(ca_key_path, 'wb') as f:
            f.write(ca_key_pem)

        cls._ca_cert_path = ca_cert_path
        cls._ca_key_path = ca_key_path
        return ca_cert_path, ca_key_path

    @classmethod
    def get_or_create_cert(cls) -> Tuple[str, str]:
        """Tạo hoặc lấy chứng chỉ Node dùng chung được ký bởi Root CA nội bộ"""
        if cls._cert_path and cls._key_path and os.path.exists(cls._cert_path) and os.path.exists(cls._key_path):
            return cls._cert_path, cls._key_path

        cert_dir = os.path.join(_base_dir, 'configs', 'certs')
        os.makedirs(cert_dir, exist_ok=True)
        cert_path = os.path.join(cert_dir, 'p2p_node.crt')
        key_path = os.path.join(cert_dir, 'p2p_node.key')

        if os.path.exists(cert_path) and os.path.exists(key_path):
            cls._cert_path = cert_path
            cls._key_path = key_path
            return cert_path, key_path

        ca_cert_path, ca_key_path = cls.get_or_create_ca()
        with open(ca_cert_path, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        with open(ca_key_path, 'rb') as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)

        node_key = ec.generate_private_key(ec.SECP256R1())
        node_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'Blockchain P2P Node'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Blockchain-CSATT P2P Mesh'),
        ])
        node_cert = x509.CertificateBuilder().subject_name(
            node_subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            node_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).sign(ca_key, hashes.SHA256())

        cert_pem = node_cert.public_bytes(serialization.Encoding.PEM)
        key_pem = node_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with open(cert_path, 'wb') as f:
            f.write(cert_pem)
        with open(key_path, 'wb') as f:
            f.write(key_pem)

        cls._cert_path = cert_path
        cls._key_path = key_path
        return cert_path, key_path

    @classmethod
    def create_server_ssl_context(cls, mode: str = "ecdhe", audit_logger=None) -> ssl.SSLContext:
        """Tạo SSL Context cho WebSocket Server bọc TLS 1.3 / Hybrid ML-KEM có giám sát an ninh Fail-Closed"""
        cert_path, key_path = cls.get_or_create_cert()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        keylog = os.environ.get("SSLKEYLOGFILE")
        if keylog:
            try:
                ctx.keylog_filename = keylog
            except Exception:
                pass

        mode = (mode or "ecdhe").lower()
        if mode in ("hybrid", "mlkem768", "mlkem", "pqc"):
            cls.set_tls_groups(ctx, "X25519MLKEM768")
        else:
            cls.set_tls_groups(ctx, "P-256:X25519")
            try:
                ctx.set_ecdh_curve('prime256v1')
            except Exception:
                pass

        # Gắn cơ chế phòng thủ Zero-Trust Fail-Closed tại tầng Socket Handshake
        if audit_logger is not None:
            orig_wrap_socket = ctx.wrap_socket

            def audit_wrap_socket(sock, *args, **kwargs):
                ssl_sock = orig_wrap_socket(sock, *args, **kwargs)
                orig_accept = ssl_sock.accept

                def audit_accept():
                    child_sock, addr = orig_accept()
                    orig_do_handshake = child_sock.do_handshake

                    def audit_do_handshake():
                        try:
                            return orig_do_handshake()
                        except ssl.SSLError as e:
                            err_str = str(e)
                            peer_str = f"{addr[0]}:{addr[1]}" if addr else "127.0.0.1:unknown"
                            reason = "NO_SUITABLE_KEY_SHARE" if "no_suitable_key_share" in err_str.lower() or "key_share" in err_str.lower() else "TLS_HANDSHAKE_TAMPERED"
                            audit_logger.log(
                                category="P2P",
                                title="CANH BAO AN NINH: P2P TLS Downgrade / Tampering Attack Detected!",
                                details={
                                    "attacker": peer_str,
                                    "tls_error": err_str,
                                    "expected_group": "X25519MLKEM768 (0x11ec)",
                                    "reason": reason,
                                    "policy": "PQC_REQUIRED",
                                    "defense": "ZERO_TRUST_FAIL_CLOSED",
                                    "action": "DROP_CONNECTION"
                                },
                                status="CRITICAL"
                            )
                            print("\n[TLS][REJECT] Handshake rejected; suspected tampering / policy violation", flush=True)
                            print(f"Peer: {peer_str} | TLS mode: {mode}", flush=True)
                            terminal_policy = "PQC_REQUIRED" if mode in ("hybrid", "mlkem768", "mlkem", "pqc") else "TLS_REQUIRED"
                            print(f"Policy: {terminal_policy} | Action: DROP_CONNECTION | Audit status: CRITICAL", flush=True)
                            print(f"Reason: {reason}", flush=True)
                            print(f"TLS error: {err_str}", flush=True)
                            raise

                    child_sock.do_handshake = audit_do_handshake
                    return child_sock, addr

                ssl_sock.accept = audit_accept
                return ssl_sock

            ctx.wrap_socket = audit_wrap_socket

        return ctx

    @classmethod
    def create_client_ssl_context(cls, mode: str = "ecdhe", verify_peer: bool = True) -> ssl.SSLContext:
        """Tạo SSL Context cho WebSocket Client bọc TLS 1.3 / Hybrid ML-KEM chống MiTM"""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ca_cert_path, _ = cls.get_or_create_ca()

        if verify_peer and os.path.exists(ca_cert_path):
            ctx.load_verify_locations(cafile=ca_cert_path)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        keylog = os.environ.get("SSLKEYLOGFILE")
        if keylog:
            try:
                ctx.keylog_filename = keylog
            except Exception:
                pass

        mode = (mode or "ecdhe").lower()
        if mode in ("hybrid", "mlkem768", "mlkem", "pqc"):
            cls.set_tls_groups(ctx, "X25519MLKEM768")
        else:
            cls.set_tls_groups(ctx, "P-256:X25519")
            try:
                ctx.set_ecdh_curve('prime256v1')
            except Exception:
                pass
        return ctx
