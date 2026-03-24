#!/usr/bin/env python3
"""
UAVLink Security & Adversarial Testing
======================================

Tests:
1. Replay Attacks - Send old valid packets to test replay window
2. MITM Attacks - Modify packet contents and test MAC verification
3. Sequence Number Attacks - Send packets with old/invalid sequences
4. Authentication Bypass - Try to inject packets without proper crypto
5. Duplicate Packet Detection - Test sliding window replay protection

This script acts as a malicious proxy between UAV and GCS.
"""

import socket
import time
import random
import struct
import copy
from collections import deque

# Network Configuration
PROXY_TELEM_PORT = 14550  # UAV sends telemetry here
PROXY_CMD_PORT = 14551     # GCS sends commands here
GCS_REAL_TELEM_PORT = 14552  # Forward telemetry to GCS
UAV_REAL_CMD_PORT = 14553    # Forward commands to UAV
IP_ADDR = "127.0.0.1"

# Attack Configuration  
REPLAY_ATTACK_RATE = 0.01      # 1% chance to replay an old packet
MITM_MODIFY_RATE = 0.005       # 0.5% chance to modify packet data
MAC_TAMPER_RATE = 0.005        # 0.5% chance to tamper with MAC
SEQUENCE_ROLLBACK_RATE = 0.005 # 0.5% chance to use old sequence
DUPLICATE_INJECT_RATE = 0.01   # 1% chance to inject duplicate

# Packet capture for replay attacks
captured_packets = {
    'uav_to_gcs': deque(maxlen=50),  # Store last 50 UAV packets
    'gcs_to_uav': deque(maxlen=50)   # Store last 50 GCS packets
}

# Attack statistics
attack_stats = {
    'replay_attempts': 0,
    'mitm_modifications': 0,
    'mac_tampers': 0,
    'sequence_rollbacks': 0,
    'duplicate_injects': 0,
    'total_packets': 0,
    'forwarded': 0
}


def parse_uavlink_header(data):
    """Parse UAVLink packet header to extract sequence number"""
    if len(data) < 4:
        return None
    
    try:
        # Byte 0: SOF (0xA5)
        if data[0] != 0xA5:
            return None
        
        # Extract sequence number from bytes 3-4
        # Byte 3 bits 1:0 contain seq[11:10]
        # Byte 4 contains seq[9:2]
        seq_hi = data[3] & 0x03
        seq_mid = data[4]
        
        sequence = (seq_hi << 10) | (seq_mid << 2)
        
        # Extract payload length (12-bit spread across bytes 1-3)
        plen_hi = (data[1] & 0xF0) >> 4
        plen_mid = (data[2] & 0x3F)
        plen_lo = (data[3] & 0xC0) >> 6
        payload_len = (plen_hi << 8) | (plen_mid << 2) | plen_lo
        
        return {
            'sequence': sequence,
            'payload_len': payload_len,
            'total_len': len(data)
        }
    except Exception as e:
        return None


def modify_packet_data(data: bytes) -> bytes:
    """MITM Attack: Modify packet contents"""
    if len(data) < 10:
        return bytes(data)
    
    modified = bytearray(data)
    
    # Choose attack type
    attack_type = random.randint(1, 3)
    
    if attack_type == 1:
        # Flip random bits in payload
        if len(modified) > 20:
            pos = random.randint(10, len(modified) - 5)
            modified[pos] ^= random.randint(1, 255)
            print(f"  [MITM] Bit flip attack at byte {pos}")
    
    elif attack_type == 2:
        # Tamper with MAC tag (last 16 bytes if present)
        if len(modified) > 20:
            mac_pos = len(modified) - random.randint(1, 16)
            modified[mac_pos] ^= 0xFF
            print(f"  [MITM] MAC tamper attack at byte {mac_pos}")
    
    elif attack_type == 3:
        # Modify sequence number
        if len(modified) >= 5:
            # Increment sequence to make it future
            modified[4] = (modified[4] + random.randint(1, 10)) & 0xFF
            print(f"  [MITM] Sequence manipulation attack")
    
    attack_stats['mitm_modifications'] += 1
    return bytes(modified)


def tamper_mac(data: bytes) -> bytes:
    """Tamper with MAC tag to test authentication"""
    if len(data) < 20:
        return bytes(data)
    
    modified = bytearray(data)
    
    # Corrupt the last 16 bytes (MAC tag)
    mac_start = len(modified) - 16
    if mac_start > 0:
        for i in range(mac_start, len(modified)):
            modified[i] ^= random.randint(1, 255)
    
    attack_stats['mac_tampers'] += 1
    print(f"  [MAC-TAMPER] Corrupted MAC authentication tag")
    return bytes(modified)


def rollback_sequence(data: bytes) -> bytes:
    """Sequence Rollback Attack: Send packet with old sequence"""
    if len(data) < 5:
        return bytes(data)
    
    modified = bytearray(data)
    
    # Roll back sequence number by 5-15
    rollback_amount = random.randint(5, 15)
    
    # Modify sequence in byte 4 (middle bits)
    current_seq = modified[4]
    new_seq = max(0, current_seq - rollback_amount)
    modified[4] = new_seq & 0xFF
    
    attack_stats['sequence_rollbacks'] += 1
    print(f"  [SEQ-ROLLBACK] Rolled back sequence by {rollback_amount}")
    return bytes(modified)


def replay_old_packet(packet_history):
    """Replay Attack: Send an old captured packet"""
    if len(packet_history) < 10:
        return None
    
    # Replay a packet from 10-40 packets ago
    age = random.randint(10, min(40, len(packet_history) - 1))
    old_packet = packet_history[-age]
    
    attack_stats['replay_attempts'] += 1
    
    header = parse_uavlink_header(old_packet['data'])
    if header:
        print(f"  [REPLAY] Replaying packet from {age} packets ago (seq={header['sequence']})")
    else:
        print(f"  [REPLAY] Replaying old packet from {age} packets ago")
    
    return old_packet['data']


def inject_duplicate(data: bytes) -> bytes:
    """Inject duplicate of current packet"""
    attack_stats['duplicate_injects'] += 1
    print(f"  [DUPLICATE] Injecting immediate duplicate")
    return bytes(data)


def print_statistics():
    """Print attack statistics"""
    print("\n" + "="*60)
    print("SECURITY TEST STATISTICS")
    print("="*60)
    print(f"Total Packets Processed:    {attack_stats['total_packets']}")
    print(f"Packets Forwarded:          {attack_stats['forwarded']}")
    print(f"\nATTACK ATTEMPTS:")
    print(f"  Replay Attacks:           {attack_stats['replay_attempts']}")
    print(f"  MITM Modifications:       {attack_stats['mitm_modifications']}")
    print(f"  MAC Tampers:              {attack_stats['mac_tampers']}")
    print(f"  Sequence Rollbacks:       {attack_stats['sequence_rollbacks']}")
    print(f"  Duplicate Injections:     {attack_stats['duplicate_injects']}")
    print(f"\nTotal Attack Attempts: {sum([attack_stats['replay_attempts'], attack_stats['mitm_modifications'], attack_stats['mac_tampers'], attack_stats['sequence_rollbacks'], attack_stats['duplicate_injects']])}")
    print("="*60 + "\n")


def adversarial_proxy():
    """Main adversarial proxy with active attacks"""
    print("="*60)
    print("UAVLink Security & Adversarial Testing Proxy")
    print("="*60)
    print(f"Intercepting UAV->GCS on {IP_ADDR}:{PROXY_TELEM_PORT}")
    print(f"Intercepting GCS->UAV on {IP_ADDR}:{PROXY_CMD_PORT}")
    print(f"\nActive Attacks:")
    print(f"  - Replay Attack Rate:      {REPLAY_ATTACK_RATE*100:.1f}%")
    print(f"  - MITM Modify Rate:        {MITM_MODIFY_RATE*100:.1f}%")
    print(f"  - MAC Tamper Rate:         {MAC_TAMPER_RATE*100:.1f}%")
    print(f"  - Sequence Rollback Rate:  {SEQUENCE_ROLLBACK_RATE*100:.1f}%")
    print(f"  - Duplicate Inject Rate:   {DUPLICATE_INJECT_RATE*100:.1f}%")
    print("="*60 + "\n")
    
    # Create sockets
    telem_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    telem_sock.bind((IP_ADDR, PROXY_TELEM_PORT))
    
    cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cmd_sock.bind((IP_ADDR, PROXY_CMD_PORT))
    
    out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    telem_sock.setblocking(False)
    cmd_sock.setblocking(False)
    
    last_stats_time = time.time()
    
    print("Adversarial proxy active - Launching attacks...\n")
    
    try:
        while True:
            # Print stats every 10 seconds
            if time.time() - last_stats_time > 10:
                print_statistics()
                last_stats_time = time.time()
            
            # Check telemetry socket (UAV -> GCS)
            try:
                data, addr = telem_sock.recvfrom(4096)
                attack_stats['total_packets'] += 1
                
                # Store in capture history
                captured_packets['uav_to_gcs'].append({
                    'data': data,
                    'time': time.time(),
                    'addr': addr
                })
                
                dest = (IP_ADDR, GCS_REAL_TELEM_PORT)
                direction = "UAV->GCS"
                
                # Decide on attack strategy
                attack_roll = random.random()
                
                if attack_roll < REPLAY_ATTACK_RATE and len(captured_packets['uav_to_gcs']) > 10:
                    # Replay old packet instead of current
                    old_packet = replay_old_packet(captured_packets['uav_to_gcs'])
                    if old_packet:
                        out_sock.sendto(old_packet, dest)
                        # Still forward original (victim might be waiting for it)
                        time.sleep(0.001)
                        out_sock.sendto(data, dest)
                        attack_stats['forwarded'] += 1
                
                elif attack_roll < REPLAY_ATTACK_RATE + MITM_MODIFY_RATE:
                    # MITM modification attack
                    modified_data = modify_packet_data(data)
                    out_sock.sendto(modified_data, dest)
                    attack_stats['forwarded'] += 1
                
                elif attack_roll < REPLAY_ATTACK_RATE + MITM_MODIFY_RATE + MAC_TAMPER_RATE:
                    # MAC tamper attack
                    tampered_data = tamper_mac(data)
                    out_sock.sendto(tampered_data, dest)
                    attack_stats['forwarded'] += 1
                
                elif attack_roll < REPLAY_ATTACK_RATE + MITM_MODIFY_RATE + MAC_TAMPER_RATE + SEQUENCE_ROLLBACK_RATE:
                    # Sequence rollback attack
                    rolled_back = rollback_sequence(data)
                    out_sock.sendto(rolled_back, dest)
                    attack_stats['forwarded'] += 1
                
                elif attack_roll < REPLAY_ATTACK_RATE + MITM_MODIFY_RATE + MAC_TAMPER_RATE + SEQUENCE_ROLLBACK_RATE + DUPLICATE_INJECT_RATE:
                    # Send duplicate immediately
                    out_sock.sendto(data, dest)
                    time.sleep(0.001)
                    duplicate = inject_duplicate(data)
                    out_sock.sendto(duplicate, dest)
                    attack_stats['forwarded'] += 1
                
                else:
                    # Forward normally (no attack)
                    out_sock.sendto(data, dest)
                    attack_stats['forwarded'] += 1
                
            except BlockingIOError:
                pass
            
            # Check command socket (GCS -> UAV)
            try:
                data, addr = cmd_sock.recvfrom(4096)
                attack_stats['total_packets'] += 1
                
                # Store in capture history
                captured_packets['gcs_to_uav'].append({
                    'data': data,
                    'time': time.time(),
                    'addr': addr
                })
                
                dest = (IP_ADDR, UAV_REAL_CMD_PORT)
                direction = "GCS->UAV"
                
                # Similar attack logic for GCS->UAV direction
                attack_roll = random.random()
                
                if attack_roll < REPLAY_ATTACK_RATE and len(captured_packets['gcs_to_uav']) > 10:
                    old_packet = replay_old_packet(captured_packets['gcs_to_uav'])
                    if old_packet:
                        out_sock.sendto(old_packet, dest)
                        time.sleep(0.001)
                        out_sock.sendto(data, dest)
                        attack_stats['forwarded'] += 1
                
                elif attack_roll < REPLAY_ATTACK_RATE + MITM_MODIFY_RATE:
                    modified_data = modify_packet_data(data)
                    out_sock.sendto(modified_data, dest)
                    attack_stats['forwarded'] += 1
                
                elif attack_roll < REPLAY_ATTACK_RATE + MITM_MODIFY_RATE + MAC_TAMPER_RATE:
                    tampered_data = tamper_mac(data)
                    out_sock.sendto(tampered_data, dest)
                    attack_stats['forwarded'] += 1
                
                else:
                    out_sock.sendto(data, dest)
                    attack_stats['forwarded'] += 1
                
            except BlockingIOError:
                pass
            
            time.sleep(0.001)  # Small delay to prevent CPU spinning
    
    except KeyboardInterrupt:
        print("\n\nStopping adversarial test...")
        print_statistics()
        print("\nTest complete!")


if __name__ == "__main__":
    try:
        adversarial_proxy()
    except KeyboardInterrupt:
        print("\nProxy stopped.")
