#!/usr/bin/env python3
"""Цели check для дыма: HTTP 80, UDP-эхо 443, DNS 53 (UDP и TCP — эхо) на адресе из argv[1].
Только на одноразовом раннере macOS (ci.yml, live-darwin); останавливается по таймауту argv[2] секунд."""
import socket
import sys
import threading
import time

ADDR = sys.argv[1]
TTL = int(sys.argv[2]) if len(sys.argv) > 2 else 600


def udp_echo(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ADDR, port))
    while True:
        data, peer = s.recvfrom(2048)
        s.sendto(data, peer)


def tcp_serve(port, reply):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ADDR, port))
    s.listen(16)
    while True:
        c, _ = s.accept()
        try:
            c.settimeout(3)
            data = c.recv(2048)
            c.sendall(reply(data))
        except OSError:
            pass
        finally:
            c.close()


def http_reply(_):
    return b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


for target, args in ((udp_echo, (443,)), (udp_echo, (53,)), (tcp_serve, (80, http_reply)), (tcp_serve, (53, lambda d: d))):
    threading.Thread(target=target, args=args, daemon=True).start()
print("targets up on", ADDR, flush=True)
time.sleep(TTL)
