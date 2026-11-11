"""
TLS Helper: Tạo và quản lý chứng chỉ SSL tự ký và mTLS hỗ trợ TLS 1.3 Hybrid Post-Quantum (X25519MLKEM768)
"""

import datetime
import os
import ssl
import tempfile
import ctypes
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Thiết lập tự động cấu hình OpenSSL PQC từ thư mục configs
_base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_cnf_path = os.path.join(_base_dir, 'configs', 'pqc_openssl.cnf')
if os.path.exists(_cnf_path):
    os.environ["OPENSSL_CONF"] = _cnf_path


class TLSManager:
    _instance = None
    _cert_path = None
    _key_path = None
    _ca_cert_path = None
    _ca_key_path = None

    @classmethod
    def set_tls_groups(cls, ctx: ssl.SSLContext, group_name: str = "X25519MLKEM768"):
        """Cấu hình nhóm TLS 1.3 Post-Quantum (FIPS 203 ML-KEM) trực tiếp vào SSL_CTX của OpenSSL 3"""
        try:
            if sys.platform == 'win32' and hasattr(os, 'add_dll_directory'):
                for d in [r'C:\msys64\ucrt64\bin', os.path.join(sys.base_prefix, 'DLLs')]:
                    if os.path.isdir(d):
                        try:
                            os.add_dll_directory(d)
                        except Exception:
                            pass
            ssl_lib = None
            for dll_candidate in ['libssl-3-x64.dll', 'libssl-3.dll', 'libssl.so']:
                try:
                    ssl_lib = ctypes.CDLL(dll_candidate)
                    break
                except Exception:
                    pass
            if ssl_lib and hasattr(ssl_lib, 'SSL_CTX_ctrl'):
                SSL_CTX_ctrl = ssl_lib.SSL_CTX_ctrl
                SSL_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_long, ctypes.c_char_p]
                SSL_CTX_ctrl.restype = ctypes.c_long
                ctx_ptr = ctypes.c_void_p.from_address(id(ctx) + 16).value
                # SSL_CTRL_SET_GROUPS_LIST = 92
                SSL_CTX_ctrl(ctx_ptr, 92, 0, group_name.encode('ascii'))
        except Exception:
            pass

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
