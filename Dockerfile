FROM python:3.11-slim

WORKDIR /app

# 1. Cai dat cac cong cu bien dich thiet yeu
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    cmake \
    ninja-build \
    libssl-dev \
    curl \
    procps \
    && rm -rf /var/lib/apt/lists/*

# 2. Bien dich thu vien Hau luong tu liboqs (Open Quantum Safe)
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
       -DBUILD_SHARED_LIBS=ON \
       -DOQS_BUILD_ONLY_LIB=ON \
       -DOQS_DIST_BUILD=ON \
    && cmake --build /tmp/liboqs/build \
    && cmake --install /tmp/liboqs/build \
    && ldconfig \
    && rm -rf /tmp/liboqs

# 3. Cai dat cac thu vien Python
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir liboqs-python

# 4. Sao chep toan bo ma nguon Blockchain
COPY . /app/

ENV HOST=0.0.0.0
ENV PORT=5000

# Expose HTTP API (5000) va Persistent WebSocket P2P (6000)
EXPOSE 5000 6000

CMD ["python", "blockchain/blockchain.py", "--host", "0.0.0.0", "-p", "5000"]
