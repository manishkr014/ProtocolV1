#!/usr/bin/env python3
"""
UAVLink 15-Minute Internal Integration Test
Launches GCS Receiver + UAV Simulator, monitors output for errors and
key metrics, then produces a test report.
"""

import subprocess
import threading
import time
import re
import sys
import os
import signal

# ---- Configuration ----
DURATION_SECONDS = 900       # 15 minutes
BIN_DIR = os.path.join(os.path.dirname(__file__), "bin")
UAV_EXE = os.path.join(BIN_DIR, "uav_simulator.exe")
GCS_EXE = os.path.join(BIN_DIR, "gcs_receiver.exe")

# ---- Shared State ----
uav_lines   = []
gcs_lines   = []
lock        = threading.Lock()

# --- Counters ---
stats = {
    "uav_packets_sent":    0,
    "gcs_packets_recv":    0,
    "ecdh_established":    0,
    "replay_detected":     0,
    "auth_fail":           0,
    "crc_errors":          0,
    "uav_crashes":         0,
    "gcs_crashes":         0,
}

ERRORS_FOUND: list[str] = []

# ---- Patterns ----
_PAT_UAV_SENT       = re.compile(r"\[TEL\]|\[CMD_ACK\]|\[SEND\]|Sending")
_PAT_GCS_RECV       = re.compile(r"\[CMD #|Received|packets_received")
_PAT_ECDH           = re.compile(r"ECDH.*Established|session key established|ESTABLISHED", re.IGNORECASE)
_PAT_REPLAY         = re.compile(r"Replay attack detected|SECURITY.*Replay", re.IGNORECASE)
_PAT_AUTH_FAIL      = re.compile(r"Authentication failed|MAC.*fail|auth_result.*-1", re.IGNORECASE)
_PAT_CRC            = re.compile(r"CRC.*error|UL_ERR_CRC", re.IGNORECASE)
_PAT_CRASH          = re.compile(r"segfault|access violation|exception|FATAL|killed", re.IGNORECASE)

def read_stream(proc, name: str, lines: list):
    """Read from a process stdout/stderr line-by-line."""
    try:
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip()
            with lock:
                lines.append((time.time(), line))
            # Classify
            if _PAT_UAV_SENT.search(line) and name == "UAV":
                stats["uav_packets_sent"] += 1
            if _PAT_GCS_RECV.search(line) and name == "GCS":
                stats["gcs_packets_recv"] += 1
            if _PAT_ECDH.search(line):
                stats["ecdh_established"] += 1
            if _PAT_REPLAY.search(line):
                stats["replay_detected"] += 1
                ERRORS_FOUND.append(f"[{name}] Replay detected: {line}")
            if _PAT_AUTH_FAIL.search(line):
                stats["auth_fail"] += 1
                ERRORS_FOUND.append(f"[{name}] Auth failure: {line}")
            if _PAT_CRC.search(line):
                stats["crc_errors"] += 1
            if _PAT_CRASH.search(line):
                if name == "UAV":
                    stats["uav_crashes"] += 1
                else:
                    stats["gcs_crashes"] += 1
                ERRORS_FOUND.append(f"[{name}] CRASH/FATAL: {line}")
    except Exception as e:
        ERRORS_FOUND.append(f"[{name}] Reader exception: {e}")


def print_progress(start: float, duration: float):
    while True:
        elapsed = time.time() - start
        remaining = max(0, duration - elapsed)
        pct = min(100, int(elapsed / duration * 100))
        bar = "#" * (pct // 5) + "." * (20 - pct // 5)
        print(f"\r  [{bar}] {pct:3d}%  elapsed={int(elapsed)}s  remaining={int(remaining)}s", end="", flush=True)
        if elapsed >= duration:
            break
        time.sleep(5)
    print()


def main():
    print("=" * 65)
    print("  UAVLink 15-Minute Internal Integration Test")
    print(f"  Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    # Check binaries exist
    for binary in (UAV_EXE, GCS_EXE):
        if not os.path.isfile(binary):
            print(f"[ERROR] Binary not found: {binary}")
            sys.exit(1)

    # Launch both processes
    print("\n  [+] Launching UAV Simulator...")
    uav_proc = subprocess.Popen(
        [UAV_EXE],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        cwd=os.path.dirname(UAV_EXE),
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )

    time.sleep(1.5)  # Give UAV time to open its socket first

    print("  [+] Launching GCS Receiver...")
    gcs_proc = subprocess.Popen(
        [GCS_EXE],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        cwd=os.path.dirname(GCS_EXE),
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )

    # Start reader threads
    uav_thread = threading.Thread(target=read_stream, args=(uav_proc, "UAV", uav_lines), daemon=True)
    gcs_thread = threading.Thread(target=read_stream, args=(gcs_proc, "GCS", gcs_lines), daemon=True)
    uav_thread.start()
    gcs_thread.start()

    start = time.time()
    print(f"\n  [+] Test running for {DURATION_SECONDS}s ({DURATION_SECONDS//60}m)...\n")
    print_progress(start, DURATION_SECONDS)

    # --- Terminate both processes ---
    print("\n  [+] Test duration reached. Terminating processes...")
    for proc in (uav_proc, gcs_proc):
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        except Exception:
            pass
        try:
            proc.terminate()
        except Exception:
            pass

    uav_proc.wait(timeout=5)
    gcs_proc.wait(timeout=5)

    total_lines = len(uav_lines) + len(gcs_lines)
    elapsed = time.time() - start

    # --- Report ---
    print("\n" + "=" * 65)
    print("  TEST REPORT")
    print("=" * 65)
    print(f"  Duration tracked : {int(elapsed)}s")
    print(f"  Total log lines  : {total_lines}")
    print()
    print("  METRICS:")
    print(f"    UAV packets sent      : {stats['uav_packets_sent']}")
    print(f"    GCS packets received  : {stats['gcs_packets_recv']}")
    print(f"    ECDH session triggers : {stats['ecdh_established']}")
    print(f"    Replay alerts         : {stats['replay_detected']}")
    print(f"    Auth failures         : {stats['auth_fail']}")
    print(f"    CRC errors            : {stats['crc_errors']}")
    print(f"    UAV crash signals     : {stats['uav_crashes']}")
    print(f"    GCS crash signals     : {stats['gcs_crashes']}")
    print()

    # ---- Tail of each process ----
    print("  LAST 15 LINES [UAV Simulator]:")
    with lock:
        for ts, line in uav_lines[-15:]:
            print(f"    {line}")

    print()
    print("  LAST 15 LINES [GCS Receiver]:")
    with lock:
        for ts, line in gcs_lines[-15:]:
            print(f"    {line}")

    print()
    if ERRORS_FOUND:
        print(f"  ISSUES DETECTED ({len(ERRORS_FOUND)}):")
        for err in ERRORS_FOUND[:30]:
            print(f"    !! {err}")
    else:
        print("  STATUS: No critical errors detected.")

    print()
    print("=" * 65)
    print("  UAVLink Integration Test Complete.")
    print("=" * 65)


if __name__ == "__main__":
    main()
