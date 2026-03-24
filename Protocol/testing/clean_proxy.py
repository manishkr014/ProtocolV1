import socket
import select
import time
import threading

# We create two distinct links
# Link 1 (Telemetry/ACKs): UAV sends to 14550 -> Proxy(14550) -> forwards to GCS(14552)
# Link 2 (Commands): GCS sends to 14551 -> Proxy(14551) -> forwards to UAV(14553)

PROXY_TELEM_PORT = 14550
PROXY_CMD_PORT = 14551
GCS_REAL_TELEM_PORT = 14552
UAV_REAL_CMD_PORT = 14553

IP_ADDR = "127.0.0.1"

def clean_forwarder():
    print(f"--- UAVLink Clean Forwarding Proxy Starting ---")
    print(f"Intercepting Telemetry on {IP_ADDR}:{PROXY_TELEM_PORT} -> Forwarding to {IP_ADDR}:{GCS_REAL_TELEM_PORT}")
    print(f"Intercepting Commands  on {IP_ADDR}:{PROXY_CMD_PORT} -> Forwarding to {IP_ADDR}:{UAV_REAL_CMD_PORT}")
    print("Zero packet loss, zero latency, NO MITM attack.")
    print("-------------------------------------------\n")

    telem_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    telem_sock.bind((IP_ADDR, PROXY_TELEM_PORT))

    cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cmd_sock.bind((IP_ADDR, PROXY_CMD_PORT))

    out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        readable, _, _ = select.select([telem_sock, cmd_sock], [], [], 0.05)

        for sock in readable:
            data, addr = sock.recvfrom(4096)
            
            if sock == telem_sock:
                dest = (IP_ADDR, GCS_REAL_TELEM_PORT)
                direction = "UAV -> GCS"
            else:
                dest = (IP_ADDR, UAV_REAL_CMD_PORT)
                direction = "GCS -> UAV"
                
            # Forward immediately without tampering or delaying
            out_sock.sendto(data, dest)

if __name__ == "__main__":
    try:
        clean_forwarder()
    except KeyboardInterrupt:
        print("\nProxy Stopped.")
