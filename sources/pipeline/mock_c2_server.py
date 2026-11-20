#!/usr/bin/env python3
"""
mock_c2_server.py - Multiplexed Lab Mock C2 Server for C1 Behavior Verifier
Thesis: Adaptive Program Transformation for Robustness Evaluation of Malware Detection Systems

Supports all Group 6 samples on 127.0.0.1:8002:
  - HTTP GET (WinINet / WinHTTP) -> HTTP 200 with dynamic C1 signature body
  - HTTP POST (WinINet)          -> HTTP 200 with dynamic C1 signature body
  - Raw TCP Stream (Winsock2)    -> Raw dynamic C1 signature payload
  - UDP Datagram (Winsock2)      -> Raw dynamic C1 signature response

Server-Dispatched Signature Pattern:
  Proof format: SAMPLE_ID|TECHNIQUE|TIMESTAMP|CHECKSUM\n
  The client writes this raw response buffer directly to C:\C1_Sandbox\c1_proof.txt.
"""

import sys
import time
import zlib
import socket
import threading

HOST = "127.0.0.1"
PORT = 8002

def generate_c1_proof(sample_id: str = "g6_c2_beacon", technique: str = "C2_Beacon") -> bytes:
    """Generate dynamic C1 signature with UNIX timestamp and CRC32 checksum."""
    unix_ts = int(time.time())
    chk_input = f"{sample_id}|{unix_ts}".encode("utf-8")
    checksum = zlib.crc32(chk_input) & 0xFFFFFFFF
    proof_line = f"{sample_id}|{technique}|{unix_ts}|{checksum:08x}\n"
    return proof_line.encode("utf-8")

def extract_sample_id(data: bytes, default_id: str = "g6_c2_beacon") -> str:
    """Extract sample_id from HTTP path/body or raw TCP beacon."""
    try:
        text = data.decode("utf-8", errors="ignore")
        if "sample_id=" in text:
            # Form post: sample_id=g6_02_http_post_wininet&...
            part = text.split("sample_id=")[1].split("&")[0].split()[0]
            return part.strip()
        elif "BEACON " in text:
            # Raw TCP/UDP: BEACON g6_04_tcp_winsock
            part = text.split("BEACON ")[1].split()[0]
            return part.strip()
        elif "g6_" in text:
            for word in text.replace("\r", " ").replace("\n", " ").split():
                if word.startswith("g6_"):
                    return word.strip()
    except Exception:
        pass
    return default_id

def handle_tcp_client(conn: socket.socket, addr):
    try:
        conn.settimeout(5.0)
        data = conn.recv(4096)
        if not data:
            return

        sample_id = extract_sample_id(data, "g6_01_http_get_wininet")
        proof = generate_c1_proof(sample_id=sample_id, technique="C2NetworkExfiltration")

        # Check if HTTP request
        if data.startswith(b"GET ") or data.startswith(b"POST "):
            http_response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n"
                b"Content-Length: " + str(len(proof)).encode("utf-8") + b"\r\n\r\n" + proof
            )
            conn.sendall(http_response)
            sys.stderr.write(f"[MockC2-HTTP] Responded to {addr} with proof for {sample_id}\n")
        else:
            # Raw TCP stream
            conn.sendall(proof)
            sys.stderr.write(f"[MockC2-TCP] Responded to {addr} with raw proof for {sample_id}\n")
    except Exception as e:
        sys.stderr.write(f"[MockC2-TCP] Error handling {addr}: {e}\n")
    finally:
        conn.close()

def run_tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    sys.stderr.write(f"[MockC2] TCP/HTTP listener active on {HOST}:{PORT}\n")

    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_tcp_client, args=(conn, addr), daemon=True)
            t.start()
        except Exception:
            break

def run_udp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((HOST, PORT))
    sys.stderr.write(f"[MockC2] UDP listener active on {HOST}:{PORT}\n")

    while True:
        try:
            data, addr = server.recvfrom(4096)
            if data:
                sample_id = extract_sample_id(data, "g6_12_udp_winsock")
                proof = generate_c1_proof(sample_id=sample_id, technique="UDPExfiltration")
                server.sendto(proof, addr)
                sys.stderr.write(f"[MockC2-UDP] Responded to {addr} with proof for {sample_id}\n")
        except Exception:
            break

def main():
    print(f"[*] Starting Unified Mock C2 Server on {HOST}:{PORT}...")
    t_udp = threading.Thread(target=run_udp_server, daemon=True)
    t_udp.start()

    try:
        run_tcp_server()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Mock C2 Server.")

if __name__ == "__main__":
    main()
