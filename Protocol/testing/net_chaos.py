import socket
import select
import random
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

# Chaos Parameters
DROP_PROBABILITY = 0.15     # 15% packet loss
DUP_PROBABILITY = 0.05      # 5% packet duplication
LATENCY_MIN_MS = 10         # Minimum delay
LATENCY_MAX_MS = 250        # Maximum delay (can cause out-of-order)

# Thread-safe queue list for delayed packets
delayed_packets = []
lock = threading.Lock()

def chaotic_forwarder():
    print(f"--- UAVLink Network Chaos Proxy Starting ---")
    print(f"Intercepting Telemetry on {IP_ADDR}:{PROXY_TELEM_PORT} -> Forwarding to {IP_ADDR}:{GCS_REAL_TELEM_PORT}")
    print(f"Intercepting Commands  on {IP_ADDR}:{PROXY_CMD_PORT} -> Forwarding to {IP_ADDR}:{UAV_REAL_CMD_PORT}")
    print(f"Parameters: {DROP_PROBABILITY*100}% Drop | {DUP_PROBABILITY*100}% Duplicate | Latency {LATENCY_MIN_MS}-{LATENCY_MAX_MS} ms")
    print("-------------------------------------------\n")

    # Socket bound to PROXY_IP to receive traffic from UAV targeting GCS (14550)
    telem_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    telem_sock.bind((IP_ADDR, PROXY_TELEM_PORT))

    # Socket bound to PROXY_IP to receive traffic from GCS targeting UAV (14551)
    cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cmd_sock.bind((IP_ADDR, PROXY_CMD_PORT))

    # Single sending socket
    out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        # Check if any delayed packets are ready to be sent
        current_time = time.time()
        with lock:
            ready_packets = [p for p in delayed_packets if p['send_time'] <= current_time]
            for p in ready_packets:
                out_sock.sendto(p['data'], p['dest'])
                delayed_packets.remove(p)

        # Select blocks until a socket has data, with a short timeout to handle delayed packets
        readable, _, _ = select.select([telem_sock, cmd_sock], [], [], 0.01)

        for sock in readable:
            data, addr = sock.recvfrom(4096)
            assert isinstance(data, bytes)
            
            # --- MITM ATTACK SIMULATION ---
            # Try to parse the base/ext header roughly to find MSG_ID 0x0A (KEY_EXCHANGE)
            if len(data) > 10 and data[0] == 0xA5:
                # We know our packet structure:
                # [0] SOF (0xA5)
                # [1-3] base header
                # [4-5] seq/sys
                # [6-7] comp/msg (MSG_ID is low 12 bits)
                msg_id = ((data[6] & 0x0F) << 8) | data[7]
                
                if msg_id == 0x00A: # UL_MSG_KEY_EXCHANGE
                    print("  [MITM] Intercepted KEY_EXCHANGE packet! Injecting malicious ECDH key...")
                    # The payload follows the header.
                    # For KEY_EXCHANGE, header is usually 9 bytes (base + seq/sys + comp/msg + target_sys).
                    # We just maliciously flip the first byte of the public key (byte 9)
                    mutable_data = bytearray(data)
                    if len(mutable_data) > 10:
                        mutable_data[9] ^= 0xFF # Flip bits of the first byte of the payload
                    data = bytes(mutable_data)
            # ------------------------------
            
            # Determine destination based on which port received the packet
            if sock == telem_sock:
                dest = (IP_ADDR, GCS_REAL_TELEM_PORT)
                direction = "UAV -> GCS"
            else:
                dest = (IP_ADDR, UAV_REAL_CMD_PORT)
                direction = "GCS -> UAV"
                
            # 1. Packet Loss
            if random.random() < DROP_PROBABILITY:
                print(f"[{direction}] X DROPPED ({len(data)} bytes)")
                continue

            # 2. Duplicate Packet
            duplicate = False
            if random.random() < DUP_PROBABILITY:
                duplicate = True

            # 3. Latency
            latency_ms = random.uniform(LATENCY_MIN_MS, LATENCY_MAX_MS)
            send_time = time.time() + (latency_ms / 1000.0)

            print(f"[{direction}] -> Delaying {latency_ms:.0f}ms ({len(data)} bytes)")
            with lock:
                delayed_packets.append({'data': data, 'dest': dest, 'send_time': send_time})
                if duplicate:
                    # Send duplicate heavily delayed
                    extra_delay = random.uniform(500, 1500)
                    dup_send_time = time.time() + (extra_delay / 1000.0)
                    delayed_packets.append({'data': data, 'dest': dest, 'send_time': dup_send_time})
                    print(f"  +-- DUP   -> Delaying {extra_delay:.0f}ms")

if __name__ == "__main__":
    try:
        chaotic_forwarder()
    except KeyboardInterrupt:
        print("\nProxy Stopped.")
