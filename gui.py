#!/usr/bin/env python3
"""
Port & ARP-RARP Scanner Tool - Professional Graphical User Interface
Pure Python (tkinter is part of the standard library)
Project: Cybersecurity Programming Course
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, font as tkfont
import threading
import queue
import logging
import json
import os
import sys
from datetime import datetime

# Import core functions from scanner
from scanner import (
    __version__, load_config, setup_logging,
    port_scan, get_arp_table, arp_scan, rarp_lookup, smart_lookup,
    parse_ports, get_network_cidr, is_valid_ip, is_valid_mac,
    get_local_ip, get_default_gateway
)

# ==================== Professional Dark Theme ====================
# Inspired by modern IDEs & security tools (GitHub Dark / Cyberpunk accent)

COLORS = {
    "bg_main":        "#0d1117",
    "bg_sidebar":     "#010409",
    "bg_panel":       "#161b22",
    "bg_card":        "#1c2128",
    "bg_input":       "#21262d",
    "bg_hover":       "#30363d",
    "bg_active":      "#388bfd26",
    "fg_primary":     "#e6edf3",
    "fg_secondary":   "#8b949e",
    "fg_muted":       "#6e7681",
    "accent":         "#58a6ff",
    "accent_hover":   "#79b8ff",
    "success":        "#3fb950",
    "success_dim":    "#238636",
    "warning":        "#d29922",
    "error":          "#f85149",
    "purple":         "#d2a8ff",
    "orange":         "#f78166",
    "border":         "#30363d",
    "border_focus":   "#58a6ff",
    "scrollbar":      "#484f58",
}

class ProfessionalScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Port & ARP-RARP Scanner  •  v{__version__}")
        self.root.geometry("1100x750")
        self.root.minsize(960, 680)
        self.root.configure(bg=COLORS["bg_main"])

        # State
        self.config = load_config()
        self.logger = setup_logging("INFO")
        self.log_level = "INFO"
        self.is_scanning = False
        self.scan_queue = queue.Queue()
        self.current_results = []
        self.scan_start_time = None

        # Center window
        self._center_window(1100, 750)

        # Build UI
        self._setup_fonts()
        self._setup_styles()
        self._build_layout()
        self._bind_shortcuts()

        # Start queue poller for thread-safe UI updates
        self.root.after(100, self._process_queue)

        # Welcome message
        self._log_welcome()

    def _center_window(self, w, h):
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _setup_fonts(self):
        self.font_title = tkfont.Font(family="Segoe UI", size=16, weight="bold")
        self.font_header = tkfont.Font(family="Segoe UI", size=11, weight="bold")
        self.font_body = tkfont.Font(family="Segoe UI", size=10)
        self.font_small = tkfont.Font(family="Segoe UI", size=9)
        self.font_mono = tkfont.Font(family="Consolas", size=10)
        self.font_mono_bold = tkfont.Font(family="Consolas", size=10, weight="bold")

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        # Global
        style.configure(".", background=COLORS["bg_main"], foreground=COLORS["fg_primary"],
                        font=self.font_body, borderwidth=0)

        style.configure("TFrame", background=COLORS["bg_main"])
        style.configure("Sidebar.TFrame", background=COLORS["bg_sidebar"])
        style.configure("Panel.TFrame", background=COLORS["bg_panel"])
        style.configure("Card.TFrame", background=COLORS["bg_card"])

        style.configure("TLabel", background=COLORS["bg_main"], foreground=COLORS["fg_primary"])
        style.configure("Sidebar.TLabel", background=COLORS["bg_sidebar"], foreground=COLORS["fg_secondary"])
        style.configure("Title.TLabel", background=COLORS["bg_main"], foreground=COLORS["accent"],
                        font=self.font_title)
        style.configure("Header.TLabel", background=COLORS["bg_panel"], foreground=COLORS["accent"],
                        font=self.font_header)
        style.configure("Muted.TLabel", background=COLORS["bg_panel"], foreground=COLORS["fg_muted"],
                        font=self.font_small)
        style.configure("Panel.TLabel", background=COLORS["bg_panel"], foreground=COLORS["fg_primary"])
        style.configure("Card.TLabel", background=COLORS["bg_card"], foreground=COLORS["fg_primary"])
        style.configure("Status.TLabel", background=COLORS["bg_main"], foreground=COLORS["fg_secondary"],
                        font=self.font_small)

        # Buttons
        style.configure("Accent.TButton", background=COLORS["accent"], foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"), padding=(14, 7))
        style.map("Accent.TButton",
                  background=[("active", COLORS["accent_hover"]), ("disabled", COLORS["bg_hover"])])

        style.configure("Success.TButton", background=COLORS["success_dim"], foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"), padding=(14, 7))
        style.map("Success.TButton", background=[("active", COLORS["success"])])

        style.configure("Danger.TButton", background="#da3633", foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"), padding=(14, 7))
        style.map("Danger.TButton", background=[("active", COLORS["error"])])

        style.configure("Ghost.TButton", background=COLORS["bg_input"], foreground=COLORS["fg_primary"],
                        font=("Segoe UI", 9), padding=(10, 5))
        style.map("Ghost.TButton", background=[("active", COLORS["bg_hover"])])

        style.configure("Nav.TButton", background=COLORS["bg_sidebar"], foreground=COLORS["fg_secondary"],
                        font=("Segoe UI", 10), padding=(16, 10), anchor="w")
        style.map("Nav.TButton",
                  background=[("active", COLORS["bg_hover"])],
                  foreground=[("active", COLORS["accent"])])

        style.configure("NavActive.TButton", background=COLORS["bg_active"], foreground=COLORS["accent"],
                        font=("Segoe UI", 10, "bold"), padding=(16, 10), anchor="w")

        # Entry / Combobox
        style.configure("TEntry", fieldbackground=COLORS["bg_input"], foreground=COLORS["fg_primary"],
                        insertcolor=COLORS["fg_primary"], borderwidth=1)
        style.configure("TCombobox", fieldbackground=COLORS["bg_input"], foreground=COLORS["fg_primary"],
                        background=COLORS["bg_input"], arrowcolor=COLORS["fg_secondary"])

        # Notebook
        style.configure("TNotebook", background=COLORS["bg_main"], borderwidth=0)
        style.configure("TNotebook.Tab", background=COLORS["bg_panel"], foreground=COLORS["fg_muted"],
                        padding=(18, 9), font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", COLORS["bg_input"])],
                  foreground=[("selected", COLORS["accent"])])

        # Progressbar
        style.configure("Horizontal.TProgressbar", background=COLORS["accent"],
                        troughcolor=COLORS["bg_input"], borderwidth=0, thickness=3)

        # Scrollbar
        style.configure("Vertical.TScrollbar", background=COLORS["bg_panel"],
                        troughcolor=COLORS["bg_main"], arrowcolor=COLORS["fg_muted"],
                        borderwidth=0)

    def _build_layout(self):
        # Main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill="both", expand=True)

        # ===== LEFT SIDEBAR =====
        self.sidebar = ttk.Frame(self.main_container, style="Sidebar.TFrame", width=200)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Logo / Title
        logo_frame = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        logo_frame.pack(fill="x", padx=16, pady=(20, 8))
        ttk.Label(logo_frame, text="⚡ SCANNER", style="Sidebar.TLabel",
                  font=("Segoe UI", 14, "bold"), foreground=COLORS["accent"]).pack(anchor="w")
        ttk.Label(logo_frame, text=f"v{__version__}  •  Pure Python", style="Sidebar.TLabel",
                  font=self.font_small).pack(anchor="w", pady=(2, 0))

        # Separator
        sep = tk.Frame(self.sidebar, height=1, bg=COLORS["border"])
        sep.pack(fill="x", padx=12, pady=12)

        # Navigation buttons
        self.nav_buttons = {}
        nav_items = [
            ("port",  "🔌  Port Scanner",   self._show_port_tab),
            ("arp",   "📡  ARP Scanner",    self._show_arp_tab),
            ("rarp",  "🔍  RARP Lookup",    self._show_rarp_tab),
        ]
        for key, label, cmd in nav_items:
            btn = ttk.Button(self.sidebar, text=label, style="Nav.TButton", command=cmd)
            btn.pack(fill="x", padx=8, pady=2)
            self.nav_buttons[key] = btn

        # Spacer
        ttk.Frame(self.sidebar, style="Sidebar.TFrame").pack(fill="both", expand=True)

        # Bottom sidebar actions
        sep2 = tk.Frame(self.sidebar, height=1, bg=COLORS["border"])
        sep2.pack(fill="x", padx=12, pady=8)

        ttk.Button(self.sidebar, text="❓  Help", style="Nav.TButton",
                   command=self._show_help).pack(fill="x", padx=8, pady=1)
        ttk.Button(self.sidebar, text="⚙️  Config", style="Nav.TButton",
                   command=self._load_config).pack(fill="x", padx=8, pady=1)
        ttk.Button(self.sidebar, text="📋  Log Level", style="Nav.TButton",
                   command=self._change_log_level).pack(fill="x", padx=8, pady=1)
        ttk.Button(self.sidebar, text="💾  Export Results", style="Nav.TButton",
                   command=self._export_results).pack(fill="x", padx=8, pady=1)

        # Developer credit — glowing animated name
        dev_sep = tk.Frame(self.sidebar, height=1, bg=COLORS["border"])
        dev_sep.pack(fill="x", padx=12, pady=(10, 6))

        self.dev_label = tk.Label(
            self.sidebar,
            text="✦  Abdulrahman Mojeeb  ✦",
            bg=COLORS["bg_sidebar"],
            fg=COLORS["accent"],
            font=("Segoe UI", 9, "bold"),
            cursor="hand2"
        )
        self.dev_label.pack(pady=(2, 4))
        tk.Label(
            self.sidebar,
            text="Developer",
            bg=COLORS["bg_sidebar"],
            fg=COLORS["fg_muted"],
            font=("Segoe UI", 7)
        ).pack(pady=(0, 10))

        self._glow_colors = [
            "#58a6ff", "#79b8ff", "#a5d6ff", "#d2a8ff",
            "#f78166", "#ffa657", "#d2a8ff", "#79b8ff"
        ]
        self._glow_index = 0
        self._animate_dev_name()

        # ===== RIGHT CONTENT AREA =====
        self.content = ttk.Frame(self.main_container)
        self.content.pack(side="left", fill="both", expand=True)

        # Top bar
        topbar = ttk.Frame(self.content)
        topbar.pack(fill="x", padx=20, pady=(14, 6))

        self.page_title = ttk.Label(topbar, text="Port Scanner", style="Title.TLabel")
        self.page_title.pack(side="left")

        # Local IP indicator
        try:
            local_ip = get_local_ip()
        except Exception:
            local_ip = "N/A"
        self.ip_label = ttk.Label(topbar, text=f"Local IP: {local_ip}", style="Status.TLabel")
        self.ip_label.pack(side="right", padx=(0, 8))

        # Content cards area (tabs will be replaced by frames)
        self.card_area = ttk.Frame(self.content, style="Panel.TFrame")
        self.card_area.pack(fill="x", padx=20, pady=6)

        # Build all tab contents (hidden by default)
        self.frames = {}
        self._build_port_frame()
        self._build_arp_frame()
        self._build_rarp_frame()

        # Show port by default
        self.current_tab = "port"
        self._show_port_tab()

        # ===== RESULTS PANEL =====
        results_container = ttk.Frame(self.content, style="Panel.TFrame")
        results_container.pack(fill="both", expand=True, padx=20, pady=(8, 6))

        results_header = ttk.Frame(results_container, style="Panel.TFrame")
        results_header.pack(fill="x", padx=12, pady=(10, 4))

        ttk.Label(results_header, text="📋  Results Console", style="Header.TLabel").pack(side="left")

        btn_frame = ttk.Frame(results_header, style="Panel.TFrame")
        btn_frame.pack(side="right")
        ttk.Button(btn_frame, text="Clear", style="Ghost.TButton",
                   command=self._clear_results).pack(side="left", padx=3)
        ttk.Button(btn_frame, text="Copy All", style="Ghost.TButton",
                   command=self._copy_results).pack(side="left", padx=3)

        # Results text — read-only (user cannot edit/delete content)
        self.results_box = scrolledtext.ScrolledText(
            results_container,
            height=14,
            bg=COLORS["bg_input"],
            fg=COLORS["fg_primary"],
            insertbackground=COLORS["fg_primary"],
            font=self.font_mono,
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            highlightbackground=COLORS["border"],
            highlightcolor=COLORS["accent"],
            padx=10,
            pady=8,
            wrap="word",
            state="disabled",
            cursor="arrow"
        )
        self.results_box.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        # Tags
        self.results_box.tag_configure("success", foreground=COLORS["success"])
        self.results_box.tag_configure("error", foreground=COLORS["error"])
        self.results_box.tag_configure("info", foreground=COLORS["accent"])
        self.results_box.tag_configure("warning", foreground=COLORS["warning"])
        self.results_box.tag_configure("header", foreground=COLORS["purple"], font=self.font_mono_bold)
        self.results_box.tag_configure("muted", foreground=COLORS["fg_muted"])
        self.results_box.tag_configure("timestamp", foreground=COLORS["fg_muted"], font=self.font_small)

        # ===== STATUS BAR =====
        status_bar = ttk.Frame(self.content)
        status_bar.pack(fill="x", padx=20, pady=(0, 12))

        self.progress = ttk.Progressbar(status_bar, mode="indeterminate", style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", side="top", pady=(0, 5))

        status_row = ttk.Frame(status_bar)
        status_row.pack(fill="x")

        self.status_var = tk.StringVar(value="Ready  •  Select a scan type from the sidebar")
        ttk.Label(status_row, textvariable=self.status_var, style="Status.TLabel").pack(side="left")

        self.log_label = ttk.Label(status_row, text=f"Log: {self.log_level}", style="Status.TLabel")
        self.log_label.pack(side="right")

        self.time_label = ttk.Label(status_row, text="", style="Status.TLabel")
        self.time_label.pack(side="right", padx=(0, 16))

    # ==================== Navigation ====================
    def _set_active_nav(self, key):
        for k, btn in self.nav_buttons.items():
            btn.configure(style="NavActive.TButton" if k == key else "Nav.TButton")
        self.current_tab = key

    def _hide_all_frames(self):
        for f in self.frames.values():
            f.pack_forget()

    def _show_port_tab(self):
        self._set_active_nav("port")
        self._hide_all_frames()
        self.page_title.configure(text="🔌  Port Scanner")
        self.frames["port"].pack(fill="x", padx=12, pady=10)

    def _show_arp_tab(self):
        self._set_active_nav("arp")
        self._hide_all_frames()
        self.page_title.configure(text="📡  ARP Scanner")
        self.frames["arp"].pack(fill="x", padx=12, pady=10)

    def _show_rarp_tab(self):
        self._set_active_nav("rarp")
        self._hide_all_frames()
        self.page_title.configure(text="🔍  RARP Lookup")
        self.frames["rarp"].pack(fill="x", padx=12, pady=10)

    # ==================== Port Frame ====================
    def _build_port_frame(self):
        f = ttk.Frame(self.card_area, style="Panel.TFrame")
        self.frames["port"] = f

        ttk.Label(f, text="Scan TCP ports on a target host or IP address",
                  style="Muted.TLabel").pack(anchor="w", padx=4, pady=(0, 10))

        # Target row
        row1 = ttk.Frame(f, style="Panel.TFrame")
        row1.pack(fill="x", pady=4)
        ttk.Label(row1, text="Target IP / Hostname", style="Panel.TLabel", width=20).pack(side="left")
        self.port_target = self._create_entry(row1)
        # Auto-detect default target for ANY user's network (gateway or local IP)
        try:
            _default_target = get_default_gateway() or get_local_ip()
            if not _default_target or _default_target.startswith("127."):
                _default_target = "192.168.1.1"
        except Exception:
            _default_target = "192.168.1.1"
        self.port_target.insert(0, _default_target)
        self.port_target.pack(side="left", fill="x", expand=True, ipady=5)

        # Ports row
        row2 = ttk.Frame(f, style="Panel.TFrame")
        row2.pack(fill="x", pady=4)
        ttk.Label(row2, text="Ports", style="Panel.TLabel", width=20).pack(side="left")
        self.port_ports = self._create_entry(row2)
        self.port_ports.insert(0, self.config.get("default_ports", "80,443,22"))
        self.port_ports.pack(side="left", fill="x", expand=True, ipady=5)

        # Timeout + Threads row
        row3 = ttk.Frame(f, style="Panel.TFrame")
        row3.pack(fill="x", pady=4)
        ttk.Label(row3, text="Timeout (sec)", style="Panel.TLabel", width=20).pack(side="left")
        self.port_timeout = self._create_entry(row3, width=10)
        self.port_timeout.insert(0, str(self.config.get("timeout", 1.0)))
        self.port_timeout.pack(side="left", ipady=5)

        ttk.Label(row3, text="    Threads", style="Panel.TLabel").pack(side="left", padx=(16, 0))
        self.port_threads = self._create_entry(row3, width=8)
        self.port_threads.insert(0, str(self.config.get("max_threads", 50)))
        self.port_threads.pack(side="left", ipady=5)

        # Action buttons
        btn_row = ttk.Frame(f, style="Panel.TFrame")
        btn_row.pack(fill="x", pady=(14, 4))
        self.port_btn = ttk.Button(btn_row, text="▶  Start Port Scan", style="Accent.TButton",
                                   command=self._run_port_scan)
        self.port_btn.pack(side="left")
        ttk.Button(btn_row, text="Common Ports", style="Ghost.TButton",
                   command=self._set_default_ports).pack(side="left", padx=8)
        ttk.Button(btn_row, text="Quick: 1-1024", style="Ghost.TButton",
                   command=lambda: self._set_ports("1-1024")).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Web Ports", style="Ghost.TButton",
                   command=lambda: self._set_ports("80,443,8080,8443")).pack(side="left", padx=4)

    def _set_default_ports(self):
        self._set_ports(self.config.get("default_ports", "80,443"))

    def _set_ports(self, value):
        self.port_ports.delete(0, tk.END)
        self.port_ports.insert(0, value)

    # ==================== ARP Frame ====================
    def _build_arp_frame(self):
        f = ttk.Frame(self.card_area, style="Panel.TFrame")
        self.frames["arp"] = f

        ttk.Label(f, text="View system ARP cache or actively discover hosts on the local network",
                  style="Muted.TLabel").pack(anchor="w", padx=4, pady=(0, 10))

        row1 = ttk.Frame(f, style="Panel.TFrame")
        row1.pack(fill="x", pady=4)
        ttk.Label(row1, text="Network Range (CIDR)", style="Panel.TLabel", width=20).pack(side="left")
        self.arp_network = self._create_entry(row1)
        # Auto-detect THIS machine's LAN CIDR (works for any network)
        try:
            self.arp_network.insert(0, get_network_cidr())
        except Exception:
            try:
                lip = get_local_ip()
                self.arp_network.insert(0, str(__import__("ipaddress").IPv4Network(f"{lip}/24", strict=False)))
            except Exception:
                self.arp_network.insert(0, "192.168.1.0/24")
        self.arp_network.pack(side="left", fill="x", expand=True, ipady=5)

        # Timeout
        row2 = ttk.Frame(f, style="Panel.TFrame")
        row2.pack(fill="x", pady=4)
        ttk.Label(row2, text="Ping Timeout (sec)", style="Panel.TLabel", width=20).pack(side="left")
        self.arp_timeout = self._create_entry(row2, width=10)
        self.arp_timeout.insert(0, str(self.config.get("ping_timeout", 1)))
        self.arp_timeout.pack(side="left", ipady=5)

        btn_row = ttk.Frame(f, style="Panel.TFrame")
        btn_row.pack(fill="x", pady=(14, 4))
        ttk.Button(btn_row, text="📋  Show ARP Table", style="Accent.TButton",
                   command=self._run_arp_table).pack(side="left")
        ttk.Button(btn_row, text="🔍  Active Network Scan", style="Success.TButton",
                   command=self._run_arp_scan).pack(side="left", padx=8)
        ttk.Button(btn_row, text="Auto-detect Network", style="Ghost.TButton",
                   command=self._auto_network).pack(side="left", padx=4)

    def _auto_network(self):
        try:
            cidr = get_network_cidr()
            self.arp_network.delete(0, tk.END)
            self.arp_network.insert(0, cidr)
        except Exception as e:
            messagebox.showerror("Error", f"Could not detect network:\n{e}")

    # ==================== RARP Frame ====================
    def _build_rarp_frame(self):
        f = ttk.Frame(self.card_area, style="Panel.TFrame")
        self.frames["rarp"] = f

        ttk.Label(f, text="RARP Lookup — MAC→IP  |  Domain→IP  |  IP→Domain (Reverse DNS)",
                  style="Muted.TLabel").pack(anchor="w", padx=4, pady=(0, 10))

        row1 = ttk.Frame(f, style="Panel.TFrame")
        row1.pack(fill="x", pady=4)
        ttk.Label(row1, text="MAC / Domain / IP", style="Panel.TLabel", width=20).pack(side="left")
        self.rarp_mac = self._create_entry(row1)
        self.rarp_mac.insert(0, "00:11:22:33:44:55")
        self.rarp_mac.pack(side="left", fill="x", expand=True, ipady=5)

        ttk.Label(f, text="MAC: 00:11:22:33:44:55  |  Domain: google.com  |  IP: 8.8.8.8",
                  style="Muted.TLabel").pack(anchor="w", padx=4, pady=(6, 0))

        btn_row = ttk.Frame(f, style="Panel.TFrame")
        btn_row.pack(fill="x", pady=(14, 4))
        ttk.Button(btn_row, text="🔎  RARP / DNS Lookup → IP", style="Accent.TButton",
                   command=self._run_rarp).pack(side="left")
        ttk.Button(btn_row, text="Example MAC", style="Ghost.TButton",
                   command=lambda: self._set_rarp_input("00:11:22:33:44:55")).pack(side="left", padx=8)
        ttk.Button(btn_row, text="Example Domain", style="Ghost.TButton",
                   command=lambda: self._set_rarp_input("google.com")).pack(side="left", padx=4)

    def _set_rarp_input(self, value):
        self.rarp_mac.delete(0, tk.END)
        self.rarp_mac.insert(0, value)

    # ==================== Helpers ====================
    def _create_entry(self, parent, width=None):
        kwargs = {
            "bg": COLORS["bg_input"],
            "fg": COLORS["fg_primary"],
            "insertbackground": COLORS["fg_primary"],
            "font": self.font_body,
            "relief": "flat",
            "highlightthickness": 1,
            "highlightbackground": COLORS["border"],
            "highlightcolor": COLORS["accent"],
        }
        if width:
            kwargs["width"] = width
        return tk.Entry(parent, **kwargs)

    def _enable_results(self):
        self.results_box.configure(state="normal")

    def _disable_results(self):
        self.results_box.configure(state="disabled")

    def _log(self, text, tag="info"):
        """Thread-safe log via queue"""
        self.scan_queue.put(("log", text, tag))

    def _log_direct(self, text, tag="info"):
        self._enable_results()
        ts = datetime.now().strftime("%H:%M:%S")
        self.results_box.insert(tk.END, f"[{ts}] ", "timestamp")
        self.results_box.insert(tk.END, text + "\n", tag)
        self.results_box.see(tk.END)
        self._disable_results()

    def _log_welcome(self):
        self._enable_results()
        self.results_box.insert(tk.END, "═" * 58 + "\n", "header")
        self.results_box.insert(tk.END, f"  Port & ARP-RARP Scanner Tool  v{__version__}\n", "header")
        self.results_box.insert(tk.END, "  Pure Python  •  No third-party libraries\n", "muted")
        self.results_box.insert(tk.END, "  Developer: Abdulrahman Mojeeb\n", "info")
        self.results_box.insert(tk.END, "═" * 58 + "\n", "header")
        self.results_box.insert(tk.END, "  Ready. Select a scan type from the sidebar.\n\n", "info")
        self._disable_results()

    def _clear_results(self):
        self._enable_results()
        self.results_box.delete("1.0", tk.END)
        self._disable_results()
        self.current_results = []
        self._log_welcome()

    def _prepare_new_scan(self):
        """Clear previous results automatically before each new operation"""
        self._enable_results()
        self.results_box.delete("1.0", tk.END)
        self._disable_results()
        self.current_results = []

    def _animate_dev_name(self):
        """Glow / pulse animation for developer name"""
        try:
            color = self._glow_colors[self._glow_index % len(self._glow_colors)]
            self.dev_label.configure(fg=color)
            self._glow_index += 1
            self.root.after(280, self._animate_dev_name)
        except Exception:
            pass

    def _copy_results(self):
        content = self.results_box.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self._set_status("Results copied to clipboard")

    def _set_status(self, text):
        self.scan_queue.put(("status", text))

    def _start_progress(self):
        self.is_scanning = True
        self.scan_start_time = datetime.now()
        self.scan_queue.put(("progress", "start"))
        self.scan_queue.put(("btn", "disable"))

    def _stop_progress(self):
        self.is_scanning = False
        self.scan_queue.put(("progress", "stop"))
        self.scan_queue.put(("btn", "enable"))

    def _process_queue(self):
        try:
            while True:
                msg = self.scan_queue.get_nowait()
                kind = msg[0]
                if kind == "log":
                    self._log_direct(msg[1], msg[2])
                elif kind == "status":
                    self.status_var.set(msg[1])
                elif kind == "progress":
                    if msg[1] == "start":
                        self.progress.start(12)
                    else:
                        self.progress.stop()
                        if self.scan_start_time:
                            elapsed = (datetime.now() - self.scan_start_time).total_seconds()
                            self.time_label.configure(text=f"Last: {elapsed:.1f}s")
                elif kind == "btn":
                    state = ["disabled"] if msg[1] == "disable" else ["!disabled"]
                    self.port_btn.state(state)
        except queue.Empty:
            pass
        self.root.after(80, self._process_queue)

    def _run_in_thread(self, func):
        if self.is_scanning:
            messagebox.showwarning("Busy", "A scan is already running.\nPlease wait until it finishes.")
            return
        # Auto-clear previous results before every new operation
        self._prepare_new_scan()
        t = threading.Thread(target=func, daemon=True)
        t.start()

    def _bind_shortcuts(self):
        self.root.bind("<Control-l>", lambda e: self._clear_results())
        self.root.bind("<Control-s>", lambda e: self._export_results())
        self.root.bind("<F1>", lambda e: self._show_help())
        self.root.bind("<Escape>", lambda e: self.root.focus())

    # ==================== Actions ====================
    def _run_port_scan(self):
        target = self.port_target.get().strip()
        ports_str = self.port_ports.get().strip()
        timeout_str = self.port_timeout.get().strip()
        threads_str = self.port_threads.get().strip()

        if not target:
            messagebox.showerror("Validation Error", "Target cannot be empty.\n\nExample: 192.168.1.1 or scanme.nmap.org")
            return

        try:
            timeout = float(timeout_str) if timeout_str else self.config.get("timeout", 1.0)
            if timeout <= 0 or timeout > 60:
                raise ValueError("Timeout out of range")
        except ValueError:
            messagebox.showerror("Validation Error", "Invalid timeout.\nMust be a number between 0.1 and 60.")
            return

        try:
            threads = int(threads_str) if threads_str else self.config.get("max_threads", 50)
            if threads < 1 or threads > 500:
                raise ValueError
        except ValueError:
            messagebox.showerror("Validation Error", "Invalid threads value.\nMust be an integer between 1 and 500.")
            return

        def task():
            self._start_progress()
            self._set_status(f"Scanning {target} ...")
            self._log("═" * 55, "header")
            self._log(f"  PORT SCAN  →  {target}", "header")
            self._log("═" * 55, "header")
            try:
                ports = parse_ports(ports_str if ports_str else self.config["default_ports"])
                result = port_scan(target, ports, timeout, threads, self.logger)
                self._log(f"Target          : {result['host']}", "info")
                self._log(f"Ports scanned   : {result['total_scanned']}", "info")
                self._log(f"Time elapsed    : {result['elapsed_seconds']} sec", "info")
                self._log("-" * 45, "muted")
                if result["open_ports"]:
                    self._log(f"Open ports ({len(result['open_ports'])}):", "success")
                    for p in result["open_ports"]:
                        self._log(f"  →  {p}/tcp", "success")
                    self.current_results.append({"type": "port", "data": result})
                else:
                    self._log("No open ports found in the specified range.", "warning")
                self._log("═" * 55, "header")
                self._set_status("Port scan completed successfully")
            except SystemExit:
                self._log("Scan aborted — invalid input.", "error")
                self._set_status("Error — invalid input")
            except Exception as e:
                self._log(f"Error: {e}", "error")
                self._set_status("Error occurred")
            finally:
                self._stop_progress()

        self._run_in_thread(task)

    def _run_arp_table(self):
        def task():
            self._start_progress()
            self._set_status("Reading system ARP table ...")
            self._log("═" * 55, "header")
            self._log("  CURRENT ARP TABLE", "header")
            self._log("═" * 55, "header")
            try:
                entries = get_arp_table(self.logger)
                if not entries:
                    self._log("No entries found in ARP table.", "warning")
                else:
                    self._log(f"{'IP Address':<18} {'MAC Address':<20} Type", "info")
                    self._log("-" * 50, "muted")
                    for e in entries:
                        self._log(f"{e['ip']:<18} {e['mac']:<20} {e.get('type', '')}")
                    self._log(f"\nTotal: {len(entries)} entries", "success")
                    self.current_results.append({"type": "arp", "data": entries})
                self._log("═" * 55, "header")
                self._set_status("ARP table loaded")
            except Exception as e:
                self._log(f"Error: {e}", "error")
                self._set_status("Error")
            finally:
                self._stop_progress()

        self._run_in_thread(task)

    def _run_arp_scan(self):
        network = self.arp_network.get().strip()
        if not network:
            messagebox.showerror("Validation Error", "Network range cannot be empty.\n\nExample: 192.168.1.0/24")
            return

        try:
            timeout = int(self.arp_timeout.get().strip() or self.config.get("ping_timeout", 1))
        except ValueError:
            timeout = self.config.get("ping_timeout", 1)

        def task():
            self._start_progress()
            self._set_status(f"Scanning network {network} ...")
            self._log("═" * 55, "header")
            self._log(f"  ARP NETWORK SCAN  →  {network}", "header")
            self._log("═" * 55, "header")
            try:
                entries = arp_scan(network, timeout,
                                   self.config.get("max_threads", 50), self.logger)
                if not entries:
                    self._log("No live hosts found.", "warning")
                else:
                    self._log(f"{'IP Address':<18} {'MAC Address':<20} Type", "info")
                    self._log("-" * 50, "muted")
                    for e in entries:
                        self._log(f"{e['ip']:<18} {e['mac']:<20} {e.get('type', '')}")
                    self._log(f"\nTotal: {len(entries)} entries", "success")
                    self.current_results.append({"type": "arp_scan", "data": entries})
                self._log("═" * 55, "header")
                self._set_status("Network scan completed")
            except SystemExit:
                self._log("Scan aborted — invalid network range.", "error")
                self._set_status("Error — invalid input")
            except Exception as e:
                self._log(f"Error: {e}", "error")
                self._set_status("Error")
            finally:
                self._stop_progress()

        self._run_in_thread(task)

    def _run_rarp(self):
        query = self.rarp_mac.get().strip()
        if not query:
            messagebox.showerror(
                "Validation Error",
                "Input cannot be empty.\n\n"
                "MAC example: 00:11:22:33:44:55\n"
                "Domain example: google.com"
            )
            return

        def task():
            self._start_progress()
            self._set_status(f"Looking up {query} ...")
            self._log("═" * 55, "header")
            self._log(f"  RARP / DNS LOOKUP  →  {query}", "header")
            self._log("═" * 55, "header")
            try:
                data = smart_lookup(query, self.logger)
                if data["mode"] == "rarp":
                    matches = data["matches"]
                    if not matches:
                        self._log("No match found in current ARP table.", "warning")
                        self._log("Tip: Ping the device first or run an ARP scan to populate the table.", "info")
                    else:
                        for e in matches:
                            self._log(f"  IP Address  : {e['ip']}", "success")
                            self._log(f"  MAC Address : {e['mac']}", "success")
                            self._log(f"  Type        : {e.get('type', 'unknown')}", "info")
                        self.current_results.append({"type": "rarp", "data": matches})
                else:
                    r = data["result"]
                    self._log(f"  Query       : {r['query']}", "info")
                    self._log(f"  Type        : {r['type']}", "info")
                    if r.get("hostname"):
                        self._log(f"  Hostname    : {r['hostname']}", "success")
                    if r.get("aliases"):
                        self._log(f"  Aliases     : {', '.join(r['aliases'])}", "info")
                    self._log(f"  Primary IP  : {r['primary_ip']}", "success")
                    if len(r.get("all_ips", [])) > 1:
                        self._log("  All IPs:", "info")
                        for ip in r["all_ips"]:
                            self._log(f"    →  {ip}", "success")
                    if r.get("type") == "ip" and not r.get("hostname"):
                        self._log("  Hostname    : (no reverse DNS record found)", "warning")
                    self.current_results.append({"type": "dns", "data": r})
                self._log("═" * 55, "header")
                self._set_status("RARP / DNS lookup completed")
            except SystemExit:
                self._log("Lookup aborted — invalid input.", "error")
                self._set_status("Error — invalid input")
            except Exception as e:
                self._log(f"Error: {e}", "error")
                self._set_status("Error")
            finally:
                self._stop_progress()

        self._run_in_thread(task)

    # ==================== Extra Features ====================
    def _export_results(self):
        content = self.results_box.get("1.0", tk.END).strip()
        if not content or "Ready. Select a scan type" in content and len(content) < 300:
            messagebox.showinfo("Export", "No results to export yet.\nRun a scan first.")
            return

        path = filedialog.asksaveasfilename(
            title="Export Results",
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("Log files", "*.log"),
                ("All files", "*.*")
            ],
            initialfile=f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(f"Port & ARP-RARP Scanner Tool v{__version__}\n")
                    f.write(f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 60 + "\n\n")
                    f.write(content)
                messagebox.showinfo("Export Successful", f"Results saved to:\n{path}")
                self._set_status(f"Exported to {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save file:\n{e}")

    def _show_help(self):
        help_win = tk.Toplevel(self.root)
        help_win.title("Help — Port & ARP-RARP Scanner")
        help_win.geometry("520x560")
        help_win.configure(bg=COLORS["bg_main"])
        help_win.resizable(False, False)
        help_win.transient(self.root)

        # Center
        help_win.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 260
        y = self.root.winfo_y() + 40
        help_win.geometry(f"+{x}+{y}")

        ttk.Label(help_win, text="⚡  Help & Documentation", style="Title.TLabel").pack(pady=(18, 8), padx=20, anchor="w")

        text = scrolledtext.ScrolledText(
            help_win, height=22, bg=COLORS["bg_input"], fg=COLORS["fg_primary"],
            font=self.font_body, relief="flat", padx=12, pady=10,
            highlightthickness=1, highlightbackground=COLORS["border"]
        )
        text.pack(fill="both", expand=True, padx=20, pady=(0, 12))

        help_content = f"""Port & ARP-RARP Scanner Tool  v{__version__}
Pure Python — No third-party libraries

═══════════════════════════════════════
  1. PORT SCANNER
═══════════════════════════════════════
Scan TCP ports on any reachable host.

• Target   : IP address or hostname
             e.g. 192.168.1.1  or  scanme.nmap.org
• Ports    : Single (80), list (22,80,443),
             or range (1-1000)
• Timeout  : Connection timeout in seconds
• Threads  : Parallel workers (1–500)

Quick buttons fill common port sets.

═══════════════════════════════════════
  2. ARP SCANNER
═══════════════════════════════════════
• Show ARP Table
  Displays the current system ARP cache
  (devices your machine already knows).

• Active Network Scan
  Pings every host in the given CIDR range,
  then reads the updated ARP table.
  Example range: 192.168.1.0/24

═══════════════════════════════════════
  3. RARP LOOKUP
═══════════════════════════════════════
• MAC address → IP (from ARP table)
  Formats: 00:11:22:33:44:55
           00-11-22-33-44-55

• Domain / Hostname → IP (DNS resolve)
  Examples: google.com
            scanme.nmap.org

Note: For MAC lookup, the device should
exist in the ARP table (run ARP scan first).

═══════════════════════════════════════
  KEYBOARD SHORTCUTS
═══════════════════════════════════════
  Ctrl+L   Clear results
  Ctrl+S   Export results
  F1       This help window
  Esc      Unfocus input fields

═══════════════════════════════════════
  CONFIG & LOG LEVEL
═══════════════════════════════════════
Use the sidebar buttons to load a JSON
config file or change logging verbosity
(DEBUG / INFO / WARNING / ERROR).

═══════════════════════════════════════
"""
        text.insert("1.0", help_content)
        text.configure(state="disabled")

        ttk.Button(help_win, text="Close", style="Accent.TButton",
                   command=help_win.destroy).pack(pady=(0, 16))

    def _load_config(self):
        path = filedialog.askopenfilename(
            title="Select config.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            new_cfg = load_config(path)
            self.config.update(new_cfg)
            # Refresh UI defaults
            self._set_default_ports()
            self.port_timeout.delete(0, tk.END)
            self.port_timeout.insert(0, str(self.config.get("timeout", 1.0)))
            self.port_threads.delete(0, tk.END)
            self.port_threads.insert(0, str(self.config.get("max_threads", 50)))
            messagebox.showinfo(
                "Config Loaded",
                f"Configuration loaded successfully!\n\n"
                f"Default ports : {str(self.config.get('default_ports', ''))[:60]}...\n"
                f"Timeout       : {self.config.get('timeout')}\n"
                f"Max threads   : {self.config.get('max_threads')}\n"
                f"Ping timeout  : {self.config.get('ping_timeout')}"
            )
            self._set_status("Config reloaded")
        except Exception as e:
            messagebox.showerror("Config Error", f"Failed to load config:\n{e}")

    def _change_log_level(self):
        win = tk.Toplevel(self.root)
        win.title("Log Level")
        win.geometry("300x200")
        win.configure(bg=COLORS["bg_main"])
        win.resizable(False, False)
        win.transient(self.root)

        win.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 150
        y = self.root.winfo_y() + 80
        win.geometry(f"+{x}+{y}")

        ttk.Label(win, text="Select logging level", style="Header.TLabel").pack(pady=(24, 10))
        var = tk.StringVar(value=self.log_level)
        combo = ttk.Combobox(win, textvariable=var,
                             values=["DEBUG", "INFO", "WARNING", "ERROR"],
                             state="readonly", width=16, font=self.font_body)
        combo.pack(pady=6)

        def apply():
            self.log_level = var.get()
            self.logger = setup_logging(self.log_level)
            self.log_label.configure(text=f"Log: {self.log_level}")
            self._set_status(f"Log level set to {self.log_level}")
            win.destroy()

        ttk.Button(win, text="Apply", style="Accent.TButton", command=apply).pack(pady=18)


def main():
    root = tk.Tk()
    # High-DPI awareness on Windows (optional, pure Python)
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    app = ProfessionalScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()