"""Materialize the captured five-network SEC-03 experiment on this machine."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import sys
import uuid
from pathlib import Path


SUITE = Path(__file__).resolve().parent
SOURCES = SUITE / "runtime_sources"


def install_missing(source, target, expected_hash, preserve_config=False):
    content = source.read_bytes()
    if hashlib.sha256(content).hexdigest() != expected_hash:
        raise RuntimeError(f"Snapshot SEC-03 bị thay đổi: {source}")
    if target.is_symlink() or target.resolve() != target:
        raise RuntimeError(f"Đường dẫn runtime chuyển hướng: {target}")
    if target.exists():
        if not target.is_file():
            raise RuntimeError(f"Runtime cần một file: {target}")
        if not preserve_config and hashlib.sha256(target.read_bytes()).hexdigest() != expected_hash:
            raise RuntimeError(
                f"Mã runtime khác snapshot: {target}. "
                "Hãy đổi tên thư mục runtime tương ứng rồi chạy lại."
            )
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f"{target.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_bytes(content)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_runtime(root, directories):
    root = Path(root).resolve()
    manifest = json.loads((SOURCES / "manifest.json").read_text(encoding="utf-8"))
    for directory in directories:
        entry = manifest["projects"][directory]
        project = root / directory
        if project.is_symlink() or project.resolve() != project:
            raise RuntimeError(f"Thư mục runtime chuyển hướng: {project}")
        for relative, digest in entry["files"].items():
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"Đường dẫn snapshot không hợp lệ: {relative}")
            install_missing(SOURCES / entry["source"] / path, project / path,
                            digest, preserve_config=path.parts[0] == "configs")
        install_missing(SUITE / "attack_sec03.py", project / "attack_sec03.py",
                        manifest["attack_sha256"])

    # The Windows library is the exact liboqs 0.16.0 DLL supplied in master.zip.
    if sys.platform == "win32" and not os.environ.get("OQS_INSTALL_PATH"):
        if struct.calcsize("P") != 8:
            raise RuntimeError("SEC-03 cần Python 64-bit để nạp oqs.dll đi kèm.")
        native = root / ".sec03-native"
        binary = native / "bin" / "oqs.dll"
        library = SUITE.parents[1] / "oqs.dll"
        if not binary.exists():
            binary.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(library, binary)
        os.environ["OQS_INSTALL_PATH"] = str(native)
        os.environ["PATH"] = str(binary.parent) + os.pathsep + os.environ.get("PATH", "")


if __name__ == "__main__":
    package_root = SUITE.parents[1]
    manifest = json.loads((SOURCES / "manifest.json").read_text(encoding="utf-8"))
    prepare_runtime(package_root, manifest["projects"])
    print("[PREPARE] Đã chuẩn bị đủ 5 runtime SEC-03.")
