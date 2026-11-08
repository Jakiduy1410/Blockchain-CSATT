"""
Blockchain Node Entrypoint
Chạy server Node:
    python blockchain.py -p 5000
    python blockchain.py -p 5001 --miner
    python blockchain.py -p 5000 --peers 127.0.0.1:5001,127.0.0.1:5002
"""

import os
import sys

# Thêm thư mục hiện tại (blockchain) và thư mục gốc vào sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)

for path in [current_dir, project_root]:
    if path not in sys.path:
        sys.path.insert(0, path)

from server import main

if __name__ == '__main__':
    main()
