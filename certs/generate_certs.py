"""
Certificate Generation Utility for Blockchain Node TLS
Generates self-signed X.509 RSA-2048 certificate and private key.
"""

import os
import subprocess
import sys
from pathlib import Path


def generate_self_signed_cert(cert_dir: Path = None) -> tuple[Path, Path]:
    if cert_dir is None:
        cert_dir = Path(__file__).resolve().parent

    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "server.crt"
    key_path = cert_dir / "server.key"

    if cert_path.exists() and key_path.exists():
        print(f"[+] TLS certificates already exist at: {cert_dir}")
        return cert_path, key_path

    print("[*] Generating new self-signed TLS certificates (RSA 2048-bit, 365 days)...")

    # Method 1: Try OpenSSL CLI
    try:
        cmd = [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(key_path),
            "-out", str(cert_path),
            "-days", "365", "-nodes",
            "-subj", "/CN=127.0.0.1/O=Blockchain-CSATT"
        ]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        print(f"[+] Successfully generated certificates via OpenSSL at: {cert_dir}")
        return cert_path, key_path
    except Exception as e:
        print(f"[-] OpenSSL CLI failed or not available ({e}).")

    raise RuntimeError("Cannot generate TLS certificate. Please install openssl or generate certs/server.crt and certs/server.key.")


if __name__ == '__main__':
    generate_self_signed_cert()
