#!/usr/bin/env python3
"""
UAVLink 3-Hour Internal Integration Test
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
DURATION_SECONDS = 10800      # 30 minutes
BIN_DIR  = os.path.join(os.path.dirname(__file__), "bin")
UAV_EXE  = os.path.join(BIN_DIR, "uav_simulator.exe")
GCS_EXE  = os.path.join(BIN_DIR, "gcs_receiver.exe")
REPORT   = os.path.join(os.path.dirname(__file__), "test_3h_report.txt")

# ---- Shared State ----
uav_lines  = []
gcs_lines  = []
lock       = threading.Lock()

stats = {
    "uav_packets_sent"   : 0,
    "gcs_packets_recv"   : 0,
    "ecdh_established"   : 0,
    "replay_detected"    : 0,
    "auth_fail"          : 0,
    "crc_errors"         : 0,
    "uav_crashes"        : 0,
    "gcs_crashes"        : 0,
    "mac_fail"           : 0,
    "compress_errors"    : 0,
    "fec_events"         : 0,
}

ERRORS_FOUND = []

# ---- Patterns ----
_PAT_UAV_SENT     = re.compile(r"\[TEL\]|\[CMD_ACK\]|\[SEND\]|Sending")
_PAT_GCS_RECV     = re.compile(r"\[CMD #|Received|packets_received")
_PAT_ECDH         = re.compile(r"ECDH.*Established|session key established|ESTABLISHED", re.IGNORECASE)
_PAT_REPLAY       = re.compile(r"Replay attack detected|SECURITY.*Replay|UL_ERR_REPLAY", re.IGNORECASE)
_PAT_AUTH_FAIL    = re.compile(r"Authentication failed|MAC.*fail|auth_result.*-1|UL_ERR_MAC", re.IGNORECASE)
_PAT_CRC          = re.compile(r"CRC.*error|UL_ERR_CRC", re.IGNORECASE)
_PAT_MAC          = re.compile(r"MAC.*verification|UL_ERR_MAC|poly1305.*fail", re.IGNORECASE)
_PAT_COMPRESS     = re.compile(r"compress.*error|decompress.*fail|FEC.*error", re.IGNORECASE)
_PAT_FEC          = re.compile(r"FEC.*recover|parity.*shard", re.IGNORECASE)
_PAT_CRASH        = re.compile(r"segfault|access violation|exception|FATAL|killed|abort", re.IGNORECASE)


def read_stream(proc, name: str, lines: list):
    try:
        for raw in iter(proc.stdout.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip()
            ts = time.time()
            with lock:
                lines.append((ts, line))
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
                ERRORS_FOUND.append(f"[{name}] CRC error: {line}")
            if _PAT_MAC.search(line):
                stats["mac_fail"] += 1
                ERRORS_FOUND.append(f"[{name}] MAC fail: {line}")
            if _PAT_COMPRESS.search(line):
                stats["compress_errors"] += 1
                ERRORS_FOUND.append(f"[{name}] Compress/FEC error: {line}")
            if _PAT_FEC.search(line):
                stats["fec_events"] += 1
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
        elapsed   = time.time() - start
        remaining = max(0, duration - elapsed)
        pct       = min(100, int(elapsed / duration * 100))
        bar       = "#" * (pct // 5) + "." * (20 - pct // 5)
        uav_sent  = stats["uav_packets_sent"]
        gcs_recv  = stats["gcs_packets_recv"]
        errors    = len(ERRORS_FOUND)
        print(
            f"\r  [{bar}] {pct:3d}%  {int(elapsed//60):02d}:{int(elapsed%60):02d}  "
            f"sent={uav_sent}  recv={gcs_recv}  errs={errors}",
            end="", flush=True,
        )
        if elapsed >= duration:
            break
        time.sleep(5)
    print()


def write_report(elapsed):
    lines_snapshot = []
    with lock:
        uav_tail = uav_lines[-20:]
        gcs_tail = gcs_lines[-20:]
        lines_snapshot = list(uav_lines) + list(gcs_lines)

    total_lines = len(lines_snapshot)
    passed = (
        stats["uav_crashes"] == 0 and
        stats["gcs_crashes"] == 0 and
        stats["auth_fail"]   == 0 and
        stats["mac_fail"]    == 0
    )

    verdict = "PASS" if passed else "FAIL"

    report_lines = [
        "=" * 65,
        "  UAVLink 3-Hour Internal Integration Test Report",
        f"  Generated : {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Verdict   : {verdict}",
        "=" * 65,
        "",
        "  DURATION & COVERAGE",
        f"    Duration tracked        : {int(elapsed)}s ({int(elapsed/60):.1f} min)",
        f"    Total log lines         : {total_lines}",
        "",
        "  METRICS",
        f"    UAV packets sent        : {stats['uav_packets_sent']}",
        f"    GCS packets received    : {stats['gcs_packets_recv']}",
        f"    ECDH session triggers   : {stats['ecdh_established']}",
        f"    FEC recovery events     : {stats['fec_events']}",
        "",
        "  SECURITY EVENTS",
        f"    Replay alerts           : {stats['replay_detected']}",
        f"    Auth / MAC failures     : {stats['auth_fail'] + stats['mac_fail']}",
        f"    CRC errors              : {stats['crc_errors']}",
        f"    Compress/FEC errors     : {stats['compress_errors']}",
        "",
        "  STABILITY",
        f"    UAV crash signals       : {stats['uav_crashes']}",
        f"    GCS crash signals       : {stats['gcs_crashes']}",
        "",
    ]

    if ERRORS_FOUND:
        report_lines.append(f"  ISSUES DETECTED ({len(ERRORS_FOUND)}):") 
        for e in ERRORS_FOUND[:50]:
            report_lines.append(f"    !! {e}")
    else:
        report_lines.append("  STATUS: No critical errors detected.")

    report_lines += [
        "",
        "  LAST 20 LINES [UAV Simulator]:",
        *[f"    {ln}" for _, ln in uav_tail],
        "",
        "  LAST 20 LINES [GCS Receiver]:",
        *[f"    {ln}" for _, ln in gcs_tail],
        "",
        "=" * 65,
        "  End of Report",
        "=" * 65,
    ]

    report_text = "\n".join(report_lines)
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write(report_text)

    return report_text, verdict


def main():
    print("=" * 65)
    print("  UAVLink 3-Hour Internal Integration Test")
    print(f"  Start time : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    for binary in (UAV_EXE, GCS_EXE):
        if not os.path.isfile(binary):
            print(f"[ERROR] Binary not found: {binary}")
            sys.exit(1)

    print("\n  [+] Launching UAV Simulator...")
    uav_proc = subprocess.Popen(
        [UAV_EXE],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        cwd=os.path.dirname(UAV_EXE),
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )
    time.sleep(1.5)

    print("  [+] Launching GCS Receiver...")
    gcs_proc = subprocess.Popen(
        [GCS_EXE],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        cwd=os.path.dirname(GCS_EXE),
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )

    uav_thread = threading.Thread(target=read_stream, args=(uav_proc, "UAV", uav_lines), daemon=True)
    gcs_thread = threading.Thread(target=read_stream, args=(gcs_proc, "GCS", gcs_lines), daemon=True)
    uav_thread.start()
    gcs_thread.start()

    start = time.time()
    print(f"\n  [+] Test running for {DURATION_SECONDS}s ({DURATION_SECONDS//60}m)...\n")
    print_progress(start, DURATION_SECONDS)

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

    elapsed = time.time() - start
    report_text, verdict = write_report(elapsed)

    print(report_text)
    print(f"\n  Report saved to: {REPORT}")


if __name__ == "__main__":
    main()
