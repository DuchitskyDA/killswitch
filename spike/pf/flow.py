"""Долгий поток для проверки отзыва состояний pf: одно и то же соединение (TCP) или 5-кортеж (UDP) живёт всё время.

flow.py tcp|tls <host> <port> <seconds> <out>      HTTP HEAD keep-alive раз в 0.5 с по одному сокету (tls — поверх TLS)
flow.py udp <host> <port> <seconds> <out> <sport>  DNS-запрос раз в 0.5 с с фиксированного порта источника
Строки в out: "<epoch> ok" | "<epoch> fail <ошибка>"; без переподключения — нужен именно старый поток.
"""

import socket
import ssl
import struct
import sys
import time


def dns_query(qid: int) -> bytes:
    name = b"".join(bytes([len(p)]) + p for p in b"example.com".split(b".")) + b"\0"
    return struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", 1, 1)


def main() -> None:
    kind, host, port, seconds, out = sys.argv[1:6]
    port_n, end = int(port), time.time() + float(seconds)
    with open(out, "a", buffering=1) as log:
        def note(s: str) -> None:
            log.write(f"{time.time():.2f} {s}\n")

        if kind in ("tcp", "tls"):
            s = socket.create_connection((host, port_n), timeout=3)
            if kind == "tls":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n".encode()
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("0.0.0.0", int(sys.argv[6])))
            s.settimeout(1.5)
        note("start")
        qid = 0
        while time.time() < end:
            try:
                if kind != "udp":
                    s.sendall(req)
                    s.settimeout(1.5)
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        chunk = s.recv(4096)
                        if not chunk:
                            raise ConnectionError("closed by peer")
                        buf += chunk
                else:
                    qid = (qid + 1) & 0xFFFF
                    s.sendto(dns_query(qid), (host, port_n))
                    s.recvfrom(4096)
                note("ok")
            except (OSError, ConnectionError, ssl.SSLError) as e:
                note(f"fail {type(e).__name__} {e}")
            time.sleep(0.5)
        note("end")


if __name__ == "__main__":
    main()
