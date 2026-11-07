#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

usable_venv() {
    [[ -f "$1/bin/activate" && -x "$1/bin/python" ]] &&
        "$1/bin/python" -c 'import sys; assert sys.prefix != sys.base_prefix' >/dev/null 2>&1
}

venv_dir=venv
if [[ -e "$venv_dir" ]] && ! usable_venv "$venv_dir"; then
    venv_dir=venv-kali
fi
if ! usable_venv "$venv_dir"; then
    if [[ -e "$venv_dir" ]]; then
        printf '[ERROR] %s không hoạt động. Hãy đổi tên thư mục đó và chạy lại.\n' "$venv_dir" >&2
        exit 1
    fi
    if ! python3 -m venv "$venv_dir"; then
        printf '[ERROR] Không tạo được venv. Trên Kali, kiểm tra gói python3-venv.\n' >&2
        exit 1
    fi
fi

source "$venv_dir/bin/activate"
"$venv_dir/bin/python" -m pip install -r requirements.txt
exec "$venv_dir/bin/python" tests/sec03_signature_integrity/run_all_attacks.py "$@"
