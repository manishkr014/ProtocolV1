#!/usr/bin/env python3
"""
UAVLink Control Center - PyQt5 Testing Dashboard
A professional GUI for managing and monitoring the UAVLink protocol.
"""

import sys
import os
import re
import time
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QTextEdit, QLabel,
                             QProgressBar, QGroupBox, QGridLayout, QFrame, QTabWidget,
                             QScrollArea)
from PyQt5.QtCore import QProcess, Qt, QTimer
from PyQt5.QtGui import QFont, QColor, QPalette, QTextCursor

# --- Constants & Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# Look for bin folder relative to script (../bin)
BIN_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "bin"))
TESTING_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "testing"))
BIN_GCS = os.path.join(BIN_DIR, "gcs_receiver.exe")
BIN_UAV = os.path.join(BIN_DIR, "uav_simulator.exe")
TEST_ADVERSARIAL = os.path.join(TESTING_DIR, "adversarial_test.py")
TEST_NET_CHAOS = os.path.join(TESTING_DIR, "net_chaos.py")
COLORS = {
    "bg": "#000000",
    "surface": "#0B0F17",
    "surface2": "#111827",
    "primary": "#4DA3FF",
    "secondary": "#23D3B0",
    "accent": "#FFB86B",
    "error": "#FF5F7E",
    "text": "#F8FAFC",
    "muted": "#A8B3C5",
    "success": "#3CF294",
    "warning": "#F6C177"
}

def format_uptime(seconds):
    if seconds is None:
        return "—"
    total = int(max(0, seconds))
    hours = total // 3600
    minutes = (total % 3600) // 60
    secs = total % 60
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"

def format_age(seconds):
    if seconds is None:
        return "—"
    if seconds < 1:
        return "<1s"
    if seconds < 60:
        return f"{int(seconds)}s"
    return f"{int(seconds // 60)}m {int(seconds % 60)}s"

# --- Styled Components ---
class StatusLabel(QLabel):
    def __init__(self, text, color=COLORS["text"]):
        super().__init__(text)
        self.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 14px;")

class GaugeWidget(QGroupBox):
    def __init__(self, title, unit="", min_val=0, max_val=100):
        super().__init__(title)
        self.unit = unit
        self.layout = QVBoxLayout()
        self.value_label = QLabel("0" + unit)
        self.value_label.setAlignment(Qt.AlignCenter)
        self.value_label.setStyleSheet(f"font-size: 22px; font-weight: 600; color: {COLORS['primary']};")
        self.progress = QProgressBar()
        self.progress.setRange(min_val * 10, max_val * 10) # 0.1 precision
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar { border: 1px solid #2B3240; border-radius: 6px; background-color: #0F131B; height: 10px; }
            QProgressBar::chunk { background-color: #23D3B0; border-radius: 6px; }
        """)
        self.layout.addWidget(self.value_label)
        self.layout.addWidget(self.progress)
        self.setLayout(self.layout)

    def set_value(self, val):
        self.value_label.setText(f"{val:.1f}{self.unit}")
        self.progress.setValue(int(val * 10))

class TerminalWidget(QTextEdit):
    def __init__(self, title):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Consolas", 10))
        self.setStyleSheet("background-color: #000000; color: #F8FAFC; border: 1px solid #2B3240;")
        self.setMinimumHeight(200)

    def append_log(self, text):
        self.moveCursor(QTextCursor.End)
        self.insertPlainText(text)
        self.moveCursor(QTextCursor.End)

# --- Main Application Window ---
class UAVLinkControlCenter(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("UAVLink Control Center v1.2")
        self.setMinimumSize(1200, 800)
        self.gcs_start_time = None
        self.uav_start_time = None
        self.last_cmd = "—"
        self.last_cmd_time = None
        self.last_hb_time = {"GCS": None, "UAV": None}
        self.hb_data = {
            "GCS": {"arm": "—", "mode": "—", "status": "—", "pkts": "0", "acks": "0", "errs": "0", "rel": "—"},
            "UAV": {"arm": "—", "mode": "—", "status": "—", "pkts": "0", "acks": "0", "errs": "0", "rel": "—"}
        }
        self.init_ui()
        self.init_processes()
        
        # UI Update Timer
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_ui_state)
        self.timer.start(100)

    def init_ui(self):
        # Apply Dark Palette
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(COLORS["bg"]))
        palette.setColor(QPalette.WindowText, QColor(COLORS["text"]))
        palette.setColor(QPalette.Base, QColor(COLORS["surface"]))
        palette.setColor(QPalette.AlternateBase, QColor(COLORS["bg"]))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, QColor(COLORS["text"]))
        palette.setColor(QPalette.Button, QColor(COLORS["surface"]))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(COLORS["primary"]))
        palette.setColor(QPalette.Highlight, QColor(COLORS["primary"]))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        self.setPalette(palette)

        main_widget = QWidget()
        main_widget.setObjectName("MainWidget")
        self.setCentralWidget(main_widget)
        root_layout = QVBoxLayout(main_widget)
        root_layout.setContentsMargins(16, 16, 16, 16)
        root_layout.setSpacing(12)

        header = QFrame()
        header.setObjectName("Header")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(12, 10, 12, 10)
        header_layout.setSpacing(12)

        title_block = QVBoxLayout()
        title = QLabel("UAVLink Control Center")
        title.setFont(QFont("Segoe UI", 18, QFont.Bold))
        subtitle = QLabel("Secure telemetry • Control • Diagnostics")
        subtitle.setStyleSheet(f"color: {COLORS['muted']};")
        title_block.addWidget(title)
        title_block.addWidget(subtitle)

        header_layout.addLayout(title_block)
        header_layout.addStretch(1)
        self.header_status = QLabel("INSECURE")
        self.header_status.setObjectName("HeaderStatus")
        self.header_status.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(self.header_status)
        root_layout.addWidget(header)

        self.main_layout = QHBoxLayout()
        self.main_layout.setSpacing(14)
        root_layout.addLayout(self.main_layout)

        self.setStyleSheet(f"""
            QWidget#MainWidget {{
                background: {COLORS['bg']};
            }}
            QFrame#Header {{
                background-color: {COLORS['surface2']};
                border: 1px solid #2B3240;
                border-radius: 10px;
            }}
            QLabel {{ color: {COLORS['text']}; }}
            QLabel#HeaderStatus {{
                background-color: {COLORS['error']};
                color: #0B0E14;
                padding: 6px 14px;
                border-radius: 12px;
                font-weight: 700;
                letter-spacing: 1px;
            }}
            QGroupBox {{
                border: 1px solid #2B3240;
                border-radius: 10px;
                margin-top: 10px;
                padding: 10px;
                background-color: {COLORS['surface']};
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 6px 0 6px;
                color: {COLORS['muted']};
                font-weight: 600;
            }}
            QPushButton {{
                background-color: {COLORS['surface2']};
                color: {COLORS['text']};
                border: 1px solid #2B3240;
                border-radius: 6px;
                padding: 6px 10px;
            }}
            QPushButton:hover {{ background-color: #202839; }}
            QTabWidget::pane {{ border: 1px solid #2B3240; border-radius: 8px; background: {COLORS['surface']}; }}
            QTabBar::tab {{
                background: {COLORS['surface2']};
                padding: 8px 14px;
                border: 1px solid #2B3240;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 4px;
                color: {COLORS['text']};
            }}
            QTabBar::tab:selected {{ background: #243046; color: {COLORS['text']}; }}
        """)

        # --- LEFT PANEL: Status & Gauges ---
        left_container = QWidget()
        left_container.setMinimumWidth(360)
        left_container.setStyleSheet(f"background-color: {COLORS['bg']};")
        left_panel = QVBoxLayout(left_container)
        left_panel.setSpacing(10)
        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setFrameShape(QFrame.NoFrame)
        left_scroll.setStyleSheet(f"QScrollArea {{ background: {COLORS['bg']}; border: 0; }} QScrollArea > QWidget {{ background: {COLORS['bg']}; }}")
        left_scroll.setWidget(left_container)
        self.main_layout.addWidget(left_scroll, 1)

        # Connection Status
        conn_group = QGroupBox("System Health")
        conn_layout = QGridLayout()
        self.gcs_status = StatusLabel("OFFLINE", COLORS["error"])
        self.uav_status = StatusLabel("OFFLINE", COLORS["error"])
        self.session_status = StatusLabel("INSECURE", COLORS["error"])
        conn_layout.addWidget(QLabel("GCS Engine:"), 0, 0)
        conn_layout.addWidget(self.gcs_status, 0, 1)
        conn_layout.addWidget(QLabel("UAV Engine:"), 1, 0)
        conn_layout.addWidget(self.uav_status, 1, 1)
        conn_layout.addWidget(QLabel("Link Security:"), 2, 0)
        conn_layout.addWidget(self.session_status, 2, 1)
        conn_group.setLayout(conn_layout)
        left_panel.addWidget(conn_group)

        # Link Overview
        link_group = QGroupBox("Link Overview")
        link_layout = QGridLayout()
        link_layout.addWidget(QLabel(""), 0, 0)
        link_layout.addWidget(QLabel("GCS"), 0, 1, alignment=Qt.AlignRight)
        link_layout.addWidget(QLabel("UAV"), 0, 2, alignment=Qt.AlignRight)
        self.link_labels = {"GCS": {}, "UAV": {}}
        rows = [
            ("ARM", "arm"),
            ("MODE", "mode"),
            ("STATUS", "status"),
            ("PKTS", "pkts"),
            ("ACKS", "acks"),
            ("ERR", "errs"),
            ("REL", "rel"),
            ("HB AGE", "age")
        ]
        for row_idx, (label, key) in enumerate(rows, start=1):
            link_layout.addWidget(QLabel(f"{label}:"), row_idx, 0)
            for col_idx, src in enumerate(["GCS", "UAV"], start=1):
                value = QLabel("—")
                value.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.link_labels[src][key] = value
                link_layout.addWidget(value, row_idx, col_idx)
        link_group.setLayout(link_layout)
        left_panel.addWidget(link_group)

        # Gauges
        gauge_layout = QGridLayout()
        self.alt_gauge = GaugeWidget("Altitude", "m", 0, 100)
        self.bat_gauge = GaugeWidget("Battery", "V", 0, 25)
        self.roll_gauge = GaugeWidget("Roll", "°", -45, 45)
        self.pitch_gauge = GaugeWidget("Pitch", "°", -45, 45)
        gauge_layout.addWidget(self.alt_gauge, 0, 0)
        gauge_layout.addWidget(self.bat_gauge, 0, 1)
        gauge_layout.addWidget(self.roll_gauge, 1, 0)
        gauge_layout.addWidget(self.pitch_gauge, 1, 1)
        left_panel.addLayout(gauge_layout)

        # Session Key info
        key_group = QGroupBox("Active Session Key")
        self.key_label = QLabel("None")
        self.key_label.setWordWrap(True)
        self.key_label.setStyleSheet(f"font-family: Consolas; color: {COLORS['secondary']};")
        key_layout = QVBoxLayout()
        key_layout.addWidget(self.key_label)
        key_group.setLayout(key_layout)
        left_panel.addWidget(key_group)

        # Process Runtime
        runtime_group = QGroupBox("Process Runtime")
        runtime_layout = QGridLayout()
        self.gcs_uptime = QLabel("—")
        self.uav_uptime = QLabel("—")
        runtime_layout.addWidget(QLabel("GCS Uptime:"), 0, 0)
        runtime_layout.addWidget(self.gcs_uptime, 0, 1)
        runtime_layout.addWidget(QLabel("UAV Uptime:"), 1, 0)
        runtime_layout.addWidget(self.uav_uptime, 1, 1)
        runtime_group.setLayout(runtime_layout)
        left_panel.addWidget(runtime_group)

        # Last Command
        cmd_group = QGroupBox("Command Stream")
        cmd_layout = QGridLayout()
        self.last_cmd_label = QLabel("—")
        self.last_cmd_time_label = QLabel("—")
        cmd_layout.addWidget(QLabel("Last Command:"), 0, 0)
        cmd_layout.addWidget(self.last_cmd_label, 0, 1)
        cmd_layout.addWidget(QLabel("Sent:"), 1, 0)
        cmd_layout.addWidget(self.last_cmd_time_label, 1, 1)
        cmd_group.setLayout(cmd_layout)
        left_panel.addWidget(cmd_group)

        # Control Buttons
        ctrl_group = QGroupBox("Quick Commands")
        ctrl_layout = QGridLayout()
        ctrl_layout.setHorizontalSpacing(10)
        ctrl_layout.setVerticalSpacing(10)
        ctrl_layout.setContentsMargins(6, 6, 6, 6)
        btn_arm = QPushButton("ARM")
        btn_disarm = QPushButton("DISARM")
        btn_takeoff = QPushButton("TAKEOFF")
        btn_land = QPushButton("LAND")
        btn_rtl = QPushButton("RTL")
        
        # Styling buttons
        for btn in [btn_arm, btn_disarm, btn_takeoff, btn_land, btn_rtl]:
            btn.setMinimumHeight(44)
            btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
            btn.setStyleSheet(
                f"background-color: {COLORS['surface2']}; color: {COLORS['primary']}; "
                f"border: 1px solid {COLORS['primary']}; padding: 6px 10px;"
            )

        btn_arm.clicked.connect(lambda: self.send_gcs_cmd("1"))
        btn_disarm.clicked.connect(lambda: self.send_gcs_cmd("2"))
        btn_takeoff.clicked.connect(lambda: self.send_gcs_cmd("3"))
        btn_land.clicked.connect(lambda: self.send_gcs_cmd("4"))
        btn_rtl.clicked.connect(lambda: self.send_gcs_cmd("5"))

        ctrl_layout.addWidget(btn_arm, 0, 0)
        ctrl_layout.addWidget(btn_disarm, 0, 1)
        ctrl_layout.addWidget(btn_takeoff, 1, 0)
        ctrl_layout.addWidget(btn_land, 1, 1)
        ctrl_layout.addWidget(btn_rtl, 2, 0, 1, 2)
        ctrl_layout.setColumnStretch(0, 1)
        ctrl_layout.setColumnStretch(1, 1)
        ctrl_group.setLayout(ctrl_layout)
        left_panel.addWidget(ctrl_group)

        # Testing Tools (Optional)
        test_group = QGroupBox("Testing Tools (Optional)")
        test_layout = QGridLayout()
        test_layout.setHorizontalSpacing(10)
        test_layout.setVerticalSpacing(10)
        test_layout.setContentsMargins(6, 6, 6, 6)
        self.adversarial_status = StatusLabel("OFFLINE", COLORS["error"])
        self.chaos_status = StatusLabel("OFFLINE", COLORS["error"])
        self.btn_toggle_adversarial = QPushButton("START ADVERSARIAL")
        self.btn_toggle_chaos = QPushButton("START NET CHAOS")
        for btn in [self.btn_toggle_adversarial, self.btn_toggle_chaos]:
            btn.setMinimumHeight(40)
            btn.setFont(QFont("Segoe UI", 9, QFont.Bold))
            btn.setStyleSheet(
                f"background-color: {COLORS['surface2']}; color: {COLORS['accent']}; "
                f"border: 1px solid {COLORS['accent']}; padding: 6px 10px;"
            )

        test_layout.addWidget(QLabel("Adversarial Proxy:"), 0, 0)
        test_layout.addWidget(self.adversarial_status, 0, 1)
        test_layout.addWidget(self.btn_toggle_adversarial, 1, 0, 1, 2)
        test_layout.addWidget(QLabel("Network Chaos:"), 2, 0)
        test_layout.addWidget(self.chaos_status, 2, 1)
        test_layout.addWidget(self.btn_toggle_chaos, 3, 0, 1, 2)
        test_layout.setColumnStretch(0, 1)
        test_layout.setColumnStretch(1, 1)
        test_group.setLayout(test_layout)
        left_panel.addWidget(test_group)
        left_panel.addStretch(1)

        # --- RIGHT PANEL: Consoles ---
        right_panel = QVBoxLayout()
        self.main_layout.addLayout(right_panel, 2)

        # Process Buttons
        proc_layout = QHBoxLayout()
        self.btn_toggle_gcs = QPushButton("START GCS")
        self.btn_toggle_uav = QPushButton("START UAV")
        
        # Consistent styling for process buttons
        for btn in [self.btn_toggle_gcs, self.btn_toggle_uav]:
            btn.setMinimumHeight(45)
            btn.setFont(QFont("Segoe UI", 10, QFont.Bold))
            btn.setStyleSheet(f"""
                QPushButton {{ 
                    background-color: {COLORS['surface2']}; 
                    color: {COLORS['secondary']}; 
                    border: 2px solid {COLORS['secondary']};
                    border-radius: 5px;
                }}
                QPushButton:hover {{ background-color: #243046; }}
            """)

        self.btn_toggle_gcs.clicked.connect(self.toggle_gcs)
        self.btn_toggle_uav.clicked.connect(self.toggle_uav)
        self.btn_toggle_adversarial.clicked.connect(self.toggle_adversarial)
        self.btn_toggle_chaos.clicked.connect(self.toggle_chaos)
        proc_layout.addWidget(self.btn_toggle_gcs)
        proc_layout.addWidget(self.btn_toggle_uav)
        right_panel.addLayout(proc_layout)

        tabs = QTabWidget()
        self.gcs_console = TerminalWidget("GCS Logs")
        self.uav_console = TerminalWidget("UAV Logs")
        self.adversarial_console = TerminalWidget("Adversarial Logs")
        self.chaos_console = TerminalWidget("Chaos Logs")
        tabs.addTab(self.gcs_console, "GCS Terminal")
        tabs.addTab(self.uav_console, "UAV Terminal")
        tabs.addTab(self.adversarial_console, "Adversarial")
        tabs.addTab(self.chaos_console, "Net Chaos")
        right_panel.addWidget(tabs)

    def closeEvent(self, event):
        """Clean up processes on exit"""
        if self.gcs_proc.state() == QProcess.Running:
            self.gcs_proc.kill()
        if self.uav_proc.state() == QProcess.Running:
            self.uav_proc.kill()
        if self.adversarial_proc.state() == QProcess.Running:
            self.adversarial_proc.kill()
        if self.chaos_proc.state() == QProcess.Running:
            self.chaos_proc.kill()
        event.accept()

    def init_processes(self):
        self.gcs_proc = QProcess()
        self.uav_proc = QProcess()
        self.adversarial_proc = QProcess()
        self.chaos_proc = QProcess()
        
        # Set working directory to project root (one level up from scripts/)
        self.project_root = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
        self.gcs_proc.setWorkingDirectory(self.project_root)
        self.uav_proc.setWorkingDirectory(self.project_root)
        self.adversarial_proc.setWorkingDirectory(self.project_root)
        self.chaos_proc.setWorkingDirectory(self.project_root)
        
        self.gcs_proc.readyReadStandardOutput.connect(self.read_gcs_out)
        self.uav_proc.readyReadStandardOutput.connect(self.read_uav_out)
        self.gcs_proc.readyReadStandardError.connect(self.read_gcs_err)
        self.uav_proc.readyReadStandardError.connect(self.read_uav_err)
        self.adversarial_proc.readyReadStandardOutput.connect(self.read_adversarial_out)
        self.adversarial_proc.readyReadStandardError.connect(self.read_adversarial_err)
        self.chaos_proc.readyReadStandardOutput.connect(self.read_chaos_out)
        self.chaos_proc.readyReadStandardError.connect(self.read_chaos_err)
        self.gcs_proc.finished.connect(lambda: self.on_proc_finished("GCS"))
        self.uav_proc.finished.connect(lambda: self.on_proc_finished("UAV"))
        self.adversarial_proc.finished.connect(lambda: self.on_proc_finished("ADVERSARIAL"))
        self.chaos_proc.finished.connect(lambda: self.on_proc_finished("CHAOS"))

    def toggle_gcs(self):
        if self.gcs_proc.state() == QProcess.NotRunning:
            # Check if binary exists
            if not os.path.exists(BIN_GCS):
                self.gcs_console.append_log(f"Error: {BIN_GCS} not found. Build it first!\n")
                return
            self.gcs_proc.start(BIN_GCS, ["127.0.0.1"])
            self.gcs_start_time = time.time()
            self.btn_toggle_gcs.setText("STOP GCS")
            self.gcs_status.setText("RUNNING")
            self.gcs_status.setStyleSheet(f"color: {COLORS['secondary']};")
        else:
            self.gcs_proc.terminate()

    def toggle_uav(self):
        if self.uav_proc.state() == QProcess.NotRunning:
            if not os.path.exists(BIN_UAV):
                self.uav_console.append_log(f"Error: {BIN_UAV} not found. Build it first!\n")
                return
            self.uav_proc.start(BIN_UAV)
            self.uav_start_time = time.time()
            self.btn_toggle_uav.setText("STOP UAV")
            self.uav_status.setText("RUNNING")
            self.uav_status.setStyleSheet(f"color: {COLORS['secondary']};")
        else:
            self.uav_proc.terminate()

    def on_proc_finished(self, name):
        try:
            if name == "GCS":
                self.gcs_start_time = None
                self.btn_toggle_gcs.setText("START GCS")
                self.gcs_status.setText("OFFLINE")
                self.gcs_status.setStyleSheet(f"color: {COLORS['error']};")
                self.set_session_secure(False)
            else:
                if name == "UAV":
                    self.uav_start_time = None
                    self.btn_toggle_uav.setText("START UAV")
                    self.uav_status.setText("OFFLINE")
                    self.uav_status.setStyleSheet(f"color: {COLORS['error']};")
                elif name == "ADVERSARIAL":
                    self.btn_toggle_adversarial.setText("START ADVERSARIAL")
                    self.adversarial_status.setText("OFFLINE")
                    self.adversarial_status.setStyleSheet(f"color: {COLORS['error']};")
                elif name == "CHAOS":
                    self.btn_toggle_chaos.setText("START NET CHAOS")
                    self.chaos_status.setText("OFFLINE")
                    self.chaos_status.setStyleSheet(f"color: {COLORS['error']};")
        except RuntimeError:
            pass # Object already deleted during shutdown

    def read_gcs_out(self):
        data = self.gcs_proc.readAllStandardOutput().data().decode()
        # Filter telemetry from visible console
        clean_lines = [l for l in data.splitlines() if not l.startswith("[TM]")]
        if clean_lines:
            self.gcs_console.append_log("\n".join(clean_lines) + "\n")
        self.parse_telemetry(data, "GCS")
        self.parse_heartbeat(data, "GCS")

    def read_uav_out(self):
        data = self.uav_proc.readAllStandardOutput().data().decode()
        # Filter telemetry from visible console
        clean_lines = [l for l in data.splitlines() if not l.startswith("[TM]")]
        if clean_lines:
            self.uav_console.append_log("\n".join(clean_lines) + "\n")
        self.parse_telemetry(data, "UAV")
        self.parse_heartbeat(data, "UAV")

    def read_gcs_err(self):
        data = self.gcs_proc.readAllStandardError().data().decode()
        if data:
            self.gcs_console.append_log("[stderr] " + data)

    def read_uav_err(self):
        data = self.uav_proc.readAllStandardError().data().decode()
        if data:
            self.uav_console.append_log("[stderr] " + data)

    def read_adversarial_out(self):
        data = self.adversarial_proc.readAllStandardOutput().data().decode()
        if data:
            self.adversarial_console.append_log(data)

    def read_adversarial_err(self):
        data = self.adversarial_proc.readAllStandardError().data().decode()
        if data:
            self.adversarial_console.append_log("[stderr] " + data)

    def read_chaos_out(self):
        data = self.chaos_proc.readAllStandardOutput().data().decode()
        if data:
            self.chaos_console.append_log(data)

    def read_chaos_err(self):
        data = self.chaos_proc.readAllStandardError().data().decode()
        if data:
            self.chaos_console.append_log("[stderr] " + data)

    def toggle_adversarial(self):
        if self.adversarial_proc.state() == QProcess.NotRunning:
            if not os.path.exists(TEST_ADVERSARIAL):
                self.adversarial_console.append_log(f"Error: {TEST_ADVERSARIAL} not found.\n")
                return
            self.adversarial_proc.start(sys.executable, [TEST_ADVERSARIAL])
            self.btn_toggle_adversarial.setText("STOP ADVERSARIAL")
            self.adversarial_status.setText("RUNNING")
            self.adversarial_status.setStyleSheet(f"color: {COLORS['secondary']};")
        else:
            self.adversarial_proc.terminate()

    def toggle_chaos(self):
        if self.chaos_proc.state() == QProcess.NotRunning:
            if not os.path.exists(TEST_NET_CHAOS):
                self.chaos_console.append_log(f"Error: {TEST_NET_CHAOS} not found.\n")
                return
            self.chaos_proc.start(sys.executable, [TEST_NET_CHAOS])
            self.btn_toggle_chaos.setText("STOP NET CHAOS")
            self.chaos_status.setText("RUNNING")
            self.chaos_status.setStyleSheet(f"color: {COLORS['secondary']};")
        else:
            self.chaos_proc.terminate()

    def parse_telemetry(self, data, source):
        # Match [TM] tags
        for line in data.splitlines():
            if line.startswith("[TM]"):
                # Handshake
                if "HANDSHAKE:ESTABLISHED" in line:
                    self.set_session_secure(True)
                
                # Session Key
                match_key = re.search(r"SESSION_KEY:([0-9A-F]+)", line)
                if match_key:
                    self.key_label.setText(match_key.group(1))
                    if self.session_status.text() != "SECURE":
                        self.set_session_secure(True)
                
                # Gauge Data (from UAV mainly)
                if source == "UAV":
                    # ALT:123 BAT:12300 ...
                    match_alt = re.search(r"ALT:(\d+)", line)
                    if match_alt: self.alt_gauge.set_value(int(match_alt.group(1)) / 1000.0)
                    match_bat = re.search(r"BAT:(\d+)", line)
                    if match_bat: self.bat_gauge.set_value(int(match_bat.group(1)) / 1000.0)
                    match_roll = re.search(r"ROLL:([-]?\d+\.\d+)", line)
                    if match_roll: self.roll_gauge.set_value(float(match_roll.group(1)))
                    match_pitch = re.search(r"PITCH:([-]?\d+\.\d+)", line)
                    if match_pitch: self.pitch_gauge.set_value(float(match_pitch.group(1)))

    def parse_heartbeat(self, data, source):
        for line in data.splitlines():
            hb_match = re.search(
                r"\[HB\]\s*(ARMED|DISARMED)\s*\|\s*([^|]+)\|\s*Status:(0x[0-9A-Fa-f]+)\s*\|\s*Pkts:(\d+)\s*ACKs:(\d+)\s*Errors:(\d+)",
                line
            )
            tm_match = re.search(
                r"HEARTBEAT:\s*(ARMED|DISARMED)-\d+\s*MODE-([A-Z0-9_]+|\d+)\s*STAT-(0x[0-9A-Fa-f]+)\s*PKTS-(\d+)\s*ERR-(\d+)",
                line
            )
            if hb_match:
                arm, mode, status, pkts, acks, errs = hb_match.groups()
                self.update_heartbeat(source, arm, mode.strip(), status, pkts, acks, errs)
            elif tm_match:
                arm, mode, status, pkts, errs = tm_match.groups()
                self.update_heartbeat(source, arm, mode, status, pkts, "0", errs)

    def update_heartbeat(self, source, arm, mode, status, pkts, acks, errs):
        self.last_hb_time[source] = time.time()
        pkts_i = int(pkts)
        errs_i = int(errs)
        rel = 100.0 if pkts_i == 0 else max(0.0, 100.0 - (errs_i / pkts_i) * 100.0)
        self.hb_data[source].update({
            "arm": arm,
            "mode": mode,
            "status": status,
            "pkts": pkts,
            "acks": acks,
            "errs": errs,
            "rel": f"{rel:.1f}%"
        })
        self.link_labels[source]["arm"].setText(arm)
        self.link_labels[source]["mode"].setText(mode)
        self.link_labels[source]["status"].setText(status)
        self.link_labels[source]["pkts"].setText(pkts)
        self.link_labels[source]["acks"].setText(acks)
        self.link_labels[source]["errs"].setText(errs)
        self.link_labels[source]["rel"].setText(f"{rel:.1f}%")
        rel_color = COLORS["success"] if rel >= 99.0 else COLORS["warning"] if rel >= 95.0 else COLORS["error"]
        self.link_labels[source]["rel"].setStyleSheet(f"color: {rel_color}; font-weight: 600;")

    def set_session_secure(self, secure):
        if secure:
            self.session_status.setText("SECURE")
            self.session_status.setStyleSheet(f"color: {COLORS['success']}; font-size: 18px;")
            self.header_status.setText("SECURE")
            self.header_status.setStyleSheet(f"background-color: {COLORS['success']}; color: #0B0E14; padding: 6px 14px; border-radius: 12px; font-weight: 700;")
        else:
            self.session_status.setText("INSECURE")
            self.session_status.setStyleSheet(f"color: {COLORS['error']}; font-size: 18px;")
            self.header_status.setText("INSECURE")
            self.header_status.setStyleSheet(f"background-color: {COLORS['error']}; color: #0B0E14; padding: 6px 14px; border-radius: 12px; font-weight: 700;")

    def send_gcs_cmd(self, cmd_char):
        if self.gcs_proc.state() == QProcess.Running:
            self.gcs_proc.write(f"{cmd_char}\n".encode())
            self.gcs_console.append_log(f"-> UI Command sent: {cmd_char}\n")
            self.last_cmd = cmd_char
            self.last_cmd_time = time.time()
            self.last_cmd_label.setText(cmd_char)

    def update_ui_state(self):
        self.gcs_uptime.setText(format_uptime(time.time() - self.gcs_start_time) if self.gcs_start_time else "—")
        self.uav_uptime.setText(format_uptime(time.time() - self.uav_start_time) if self.uav_start_time else "—")

        for src in ["GCS", "UAV"]:
            age = None if self.last_hb_time[src] is None else time.time() - self.last_hb_time[src]
            self.link_labels[src]["age"].setText(format_age(age))

        if self.last_cmd_time is None:
            self.last_cmd_time_label.setText("—")
        else:
            self.last_cmd_time_label.setText(format_age(time.time() - self.last_cmd_time))

if __name__ == "__main__":
    # Fix for scaling on high-DPI screens
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    window = UAVLinkControlCenter()
    window.show()
    sys.exit(app.exec_())
