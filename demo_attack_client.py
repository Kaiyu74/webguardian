#!/usr/bin/env python3

"""
Helper script to exercise the WebGuardian middlebox with realistic attack probes.
The script sends crafted HTTP requests to a target web server so you can watch
the detection pipeline flag the traffic in real time.
"""

import argparse
import socket
from typing import Dict


PAYLOADS: Dict[str, str] = {
    "sql_injection": "username=admin' OR 1=1--&password=irrelevant",
    "xss": "search=<script>alert('xss')</script>",
    "command_injection": "cmd=ls|whoami",
    "path_traversal": "file=../../../../etc/passwd",
    "deserialization": "payload=O:8:\"Exploit\":1:{s:4:\"eval\";s:11:\"phpinfo();\"}",
}


def build_request(host: str, payload: str) -> bytes:
    request_line = f"GET /vuln?{payload} HTTP/1.1\r\n"
    headers = (
        f"Host: {host}\r\n"
        "User-Agent: WebGuardian-Demo/1.0\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return (request_line + headers).encode("utf-8")


def send_probe(host: str, port: int, payload_key: str) -> None:
    payload = PAYLOADS[payload_key]
    request = build_request(host, payload)
    with socket.create_connection((host, port)) as client:
        client.sendall(request)
        # Consume response quietly; the target server might just close the socket.
        try:
            client.recv(1024)
        except ConnectionResetError:
            pass
    print(f"Sent {payload_key} payload to {host}:{port}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send canned attack payloads to exercise the middlebox detector.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("host", help="Target host running an HTTP service.")
    parser.add_argument("port", type=int, help="Target HTTP port.")
    parser.add_argument(
        "--payload",
        choices=list(PAYLOADS.keys()) + ["all"],
        default="all",
        help="Attack payload to send.",
    )
    args = parser.parse_args()

    if args.payload == "all":
        for key in PAYLOADS:
            send_probe(args.host, args.port, key)
    else:
        send_probe(args.host, args.port, args.payload)


if __name__ == "__main__":
    main()

