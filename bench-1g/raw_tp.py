#!/usr/bin/env python3
"""Raw TCP throughput: optional sender (bind 10.0.0.1 -> connect 10.0.0.2) || receiver (listen 10.0.0.2)."""
import socket, sys, time

SENDER_IP = "10.0.0.1"
RECV_IP = "10.0.0.2"
PORT = 9999
TOTAL_MB = 1024  # 1 GiB

def receiver():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((RECV_IP, PORT))
    s.listen(1)
    conn, _ = s.accept()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    total = 0
    start = time.time()
    buf = conn.recv(1 << 20)
    while buf:
        total += len(buf)
        buf = conn.recv(1 << 20)
    dur = time.time() - start
    print(f"RECEIVED {total/1e6:.1f} MB in {dur:.3f}s = {total*8/dur/1e6:.1f} Mbps", flush=True)

def sender():
    c = socket.socket()
    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    c.bind((SENDER_IP, 0))
    c.settimeout(15)
    c.connect((RECV_IP, PORT))
    chunk = b"\x00" * (1 << 20)
    target = TOTAL_MB * (1 << 20)
    sent = 0
    start = time.time()
    while sent < target:
        n = c.send(chunk)
        if n <= 0:
            break
        sent += n
    c.close()
    dur = time.time() - start
    print(f"SENT {sent/1e6:.1f} MB in {dur:.3f}s = {sent*8/dur/1e6:.1f} Mbps", flush=True)

if __name__ == "__main__":
    (receiver if sys.argv[1] == "recv" else sender)()