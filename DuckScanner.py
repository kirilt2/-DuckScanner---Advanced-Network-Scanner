#!/usr/bin/env python3
"""
DuckScanner - Advanced Network Scanner 🦆
A comprehensive network scanning tool with modern GUI
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import threading
import time
import json
import csv
import subprocess
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import os
import sys

class DuckScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("DuckScanner 🦆 - Advanced Network Scanner")
        self.root.geometry("1400x900")
        self.root.configure(bg='#0d1117')
        self.root.minsize(1200, 800)
        
        # Variables
        self.target_var = tk.StringVar()
        self.ports_var = tk.StringVar(value="1-1000")
        self.threads_var = tk.IntVar(value=100)
        self.timeout_var = tk.DoubleVar(value=1.0)
        self.scan_type_var = tk.StringVar(value="TCP Connect")
        self.is_scanning = False
        self.scan_results = []
        self.scan_history = []
        
        # Service database
        self.services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9090: 'Openfire',
            1433: 'MSSQL', 1521: 'Oracle', 5433: 'PostgreSQL-Alt',
            6379: 'Redis', 27017: 'MongoDB', 9200: 'Elasticsearch'
        }
        
        self.setup_ui()
        self.load_scan_history()
        
    def setup_ui(self):
        """Setup the modern user interface"""
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Custom color scheme
        self.colors = {
            'bg_primary': '#0d1117',
            'bg_secondary': '#161b22',
            'bg_tertiary': '#21262d',
            'accent': '#58a6ff',
            'accent_hover': '#79c0ff',
            'success': '#7ee787',
            'warning': '#ffa657',
            'error': '#f85149',
            'text_primary': '#f0f6fc',
            'text_secondary': '#8b949e',
            'border': '#30363d'
        }
        
        # Configure styles
        style.configure('Title.TLabel', font=('Segoe UI', 28, 'bold'), 
                       background=self.colors['bg_primary'], foreground=self.colors['accent'])
        style.configure('Subtitle.TLabel', font=('Segoe UI', 12), 
                       background=self.colors['bg_primary'], foreground=self.colors['text_secondary'])
        style.configure('Header.TLabel', font=('Segoe UI', 12, 'bold'), 
                       background=self.colors['bg_secondary'], foreground=self.colors['text_primary'])
        style.configure('Custom.TButton', font=('Segoe UI', 10, 'bold'))
        style.configure('Success.TButton', font=('Segoe UI', 10, 'bold'))
        style.configure('Warning.TButton', font=('Segoe UI', 10, 'bold'))
        style.configure('Error.TButton', font=('Segoe UI', 10, 'bold'))
        
        # Main container
        main_container = tk.Frame(self.root, bg=self.colors['bg_primary'])
        main_container.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Header with gradient effect
        header_frame = tk.Frame(main_container, bg=self.colors['bg_secondary'], relief='raised', bd=1)
        header_frame.pack(fill='x', pady=(0, 20))
        
        # Title section
        title_frame = tk.Frame(header_frame, bg=self.colors['bg_secondary'])
        title_frame.pack(fill='x', padx=20, pady=15)
        
        title_label = ttk.Label(title_frame, text="🦆 DuckScanner", style='Title.TLabel')
        title_label.pack()
        
        subtitle_label = ttk.Label(title_frame, text="Advanced Network Scanner & Security Tool", style='Subtitle.TLabel')
        subtitle_label.pack()
        
        # Creator credit
        creator_label = ttk.Label(title_frame, text="Created by Kirill Tikhomirov", 
                                font=('Segoe UI', 10, 'italic'), 
                                background=self.colors['bg_secondary'], 
                                foreground=self.colors['text_secondary'])
        creator_label.pack(pady=(5, 0))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill='both', expand=True)
        
        # Port Scanner Tab
        self.create_port_scanner_tab()
        
        # Network Discovery Tab
        self.create_network_discovery_tab()
        
        # Service Detection Tab
        self.create_service_detection_tab()
        
        # Scan History Tab
        self.create_scan_history_tab()
        
        # Settings Tab
        self.create_settings_tab()
        
        # Status bar
        self.create_status_bar()
        
    def create_port_scanner_tab(self):
        """Create the main port scanner tab"""
        port_frame = ttk.Frame(self.notebook)
        self.notebook.add(port_frame, text="🔍 Port Scanner")
        
        # Left panel - Configuration
        left_panel = tk.Frame(port_frame, bg=self.colors['bg_secondary'], relief='raised', bd=1)
        left_panel.pack(side='left', fill='y', padx=(0, 10))
        left_panel.configure(width=380)
        left_panel.pack_propagate(False)
        
        # Configuration section
        config_frame = tk.LabelFrame(left_panel, text="⚙️ Scan Configuration", 
                                   font=('Segoe UI', 12, 'bold'), bg=self.colors['bg_tertiary'], 
                                   fg=self.colors['text_primary'], relief='raised', bd=2)
        config_frame.pack(fill='x', padx=15, pady=15)
        
        # Target input
        tk.Label(config_frame, text="🎯 Target:", font=('Segoe UI', 10, 'bold'), 
                bg=self.colors['bg_tertiary'], fg=self.colors['text_primary']).pack(anchor='w', padx=10, pady=(10, 5))
        target_entry = tk.Entry(config_frame, textvariable=self.target_var, 
                              font=('Segoe UI', 10), width=42, bg=self.colors['bg_primary'], 
                              fg=self.colors['text_primary'], insertbackground=self.colors['text_primary'],
                              relief='solid', bd=1, highlightthickness=2, 
                              highlightcolor=self.colors['accent'])
        target_entry.pack(padx=10, pady=(0, 10))
        
        # Port input
        tk.Label(config_frame, text="🔌 Ports:", font=('Segoe UI', 10, 'bold'), 
                bg=self.colors['bg_tertiary'], fg=self.colors['text_primary']).pack(anchor='w', padx=10, pady=(5, 5))
        ports_entry = tk.Entry(config_frame, textvariable=self.ports_var, 
                             font=('Segoe UI', 10), width=42, bg=self.colors['bg_primary'], 
                             fg=self.colors['text_primary'], insertbackground=self.colors['text_primary'],
                             relief='solid', bd=1, highlightthickness=2, 
                             highlightcolor=self.colors['accent'])
        ports_entry.pack(padx=10, pady=(0, 10))
        
        # Scan type
        tk.Label(config_frame, text="⚡ Scan Type:", font=('Segoe UI', 10, 'bold'), 
                bg=self.colors['bg_tertiary'], fg=self.colors['text_primary']).pack(anchor='w', padx=10, pady=(5, 5))
        scan_type_combo = ttk.Combobox(config_frame, textvariable=self.scan_type_var,
                                     values=["TCP Connect", "TCP SYN", "UDP", "Stealth"],
                                     state="readonly", width=39, font=('Segoe UI', 10))
        scan_type_combo.pack(padx=10, pady=(0, 10))
        
        # Advanced settings
        advanced_frame = tk.LabelFrame(config_frame, text="🔧 Advanced Settings", 
                                     font=('Segoe UI', 10, 'bold'), bg=self.colors['bg_primary'], 
                                     fg=self.colors['text_primary'], relief='flat', bd=1)
        advanced_frame.pack(fill='x', padx=10, pady=10)
        
        # Threads
        tk.Label(advanced_frame, text="🧵 Threads:", font=('Segoe UI', 9, 'bold'), 
                bg=self.colors['bg_primary'], fg=self.colors['text_primary']).grid(row=0, column=0, sticky='w', padx=10, pady=8)
        threads_spinbox = tk.Spinbox(advanced_frame, from_=1, to=500, 
                                   textvariable=self.threads_var, width=12, bg=self.colors['bg_secondary'], 
                                   fg=self.colors['text_primary'], font=('Segoe UI', 9),
                                   relief='solid', bd=1, highlightthickness=1,
                                   highlightcolor=self.colors['accent'])
        threads_spinbox.grid(row=0, column=1, padx=10, pady=8)
        
        # Timeout
        tk.Label(advanced_frame, text="⏱️ Timeout:", font=('Segoe UI', 9, 'bold'), 
                bg=self.colors['bg_primary'], fg=self.colors['text_primary']).grid(row=1, column=0, sticky='w', padx=10, pady=8)
        timeout_spinbox = tk.Spinbox(advanced_frame, from_=0.1, to=10.0, increment=0.1,
                                   textvariable=self.timeout_var, width=12, bg=self.colors['bg_secondary'], 
                                   fg=self.colors['text_primary'], font=('Segoe UI', 9),
                                   relief='solid', bd=1, highlightthickness=1,
                                   highlightcolor=self.colors['accent'])
        timeout_spinbox.grid(row=1, column=1, padx=10, pady=8)
        
        # Preset buttons
        presets_frame = tk.LabelFrame(left_panel, text="⚡ Quick Presets", 
                                    font=('Segoe UI', 10, 'bold'), bg=self.colors['bg_tertiary'], 
                                    fg=self.colors['text_primary'], relief='raised', bd=2)
        presets_frame.pack(fill='x', padx=15, pady=10)
        
        presets = [
            ("🌐 Common", "22,23,25,53,80,110,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080"),
            ("🌍 Web", "80,443,8080,8443,8000,8008,8081,9080,9443"),
            ("🗄️ Database", "1433,1521,3306,5432,6379,27017,9200"),
            ("🔍 All Ports", "1-65535")
        ]
        
        for i, (name, ports) in enumerate(presets):
            btn = tk.Button(presets_frame, text=name, command=lambda p=ports: self.set_ports(p),
                          bg=self.colors['accent'], fg='#ffffff', font=('Segoe UI', 9, 'bold'), 
                          width=16, height=1, relief='raised', bd=2,
                          activebackground=self.colors['accent_hover'])
            btn.grid(row=i//2, column=i%2, padx=5, pady=5, sticky='ew')
        
        presets_frame.columnconfigure(0, weight=1)
        presets_frame.columnconfigure(1, weight=1)
        
        # Control buttons
        control_frame = tk.Frame(left_panel, bg=self.colors['bg_secondary'])
        control_frame.pack(fill='x', padx=15, pady=15)
        
        self.scan_button = tk.Button(control_frame, text="🚀 Start Scan", 
                                   command=self.start_scan, bg=self.colors['success'], fg='#000000',
                                   font=('Segoe UI', 12, 'bold'), padx=25, pady=8, 
                                   relief='raised', bd=3, activebackground='#6dd47e')
        self.scan_button.pack(side='left', padx=5)
        
        clear_button = tk.Button(control_frame, text="🗑️ Clear", 
                               command=self.clear_results, bg=self.colors['error'], fg='#ffffff',
                               font=('Segoe UI', 10, 'bold'), padx=20, pady=8,
                               relief='raised', bd=2, activebackground='#ff4757')
        clear_button.pack(side='left', padx=5)
        
        export_button = tk.Button(control_frame, text="💾 Export", 
                                command=self.export_results, bg=self.colors['accent'], fg='#ffffff',
                                font=('Segoe UI', 10, 'bold'), padx=20, pady=8,
                                relief='raised', bd=2, activebackground=self.colors['accent_hover'])
        export_button.pack(side='left', padx=5)
        
        # Right panel - Results
        right_panel = tk.Frame(port_frame, bg=self.colors['bg_primary'])
        right_panel.pack(side='right', fill='both', expand=True)
        
        # Results header
        results_header = tk.Frame(right_panel, bg=self.colors['bg_secondary'], height=50, relief='raised', bd=2)
        results_header.pack(fill='x', pady=(0, 10))
        results_header.pack_propagate(False)
        
        tk.Label(results_header, text="📊 Scan Results", font=('Segoe UI', 16, 'bold'), 
                bg=self.colors['bg_secondary'], fg=self.colors['text_primary']).pack(side='left', padx=15, pady=15)
        
        # Progress bar
        self.progress_var = tk.StringVar(value="Ready to scan")
        progress_label = tk.Label(results_header, textvariable=self.progress_var, 
                                font=('Segoe UI', 10, 'bold'), bg=self.colors['bg_secondary'], 
                                fg=self.colors['accent'])
        progress_label.pack(side='right', padx=15, pady=15)
        
        self.progress_bar = ttk.Progressbar(right_panel, mode='indeterminate', 
                                          style='TProgressbar')
        self.progress_bar.pack(fill='x', pady=(0, 10))
        
        # Results text area with better styling
        self.results_text = scrolledtext.ScrolledText(
            right_panel, font=('Consolas', 11), bg=self.colors['bg_primary'], 
            fg=self.colors['text_primary'], insertbackground=self.colors['text_primary'], 
            wrap=tk.WORD, relief='solid', bd=2, highlightthickness=2,
            highlightcolor=self.colors['accent']
        )
        self.results_text.pack(fill='both', expand=True)
        
        # Configure text tags for colored output
        self.results_text.tag_configure("open", foreground=self.colors['success'], font=('Consolas', 11, 'bold'))
        self.results_text.tag_configure("closed", foreground=self.colors['error'], font=('Consolas', 11))
        self.results_text.tag_configure("error", foreground=self.colors['warning'], font=('Consolas', 11, 'bold'))
        self.results_text.tag_configure("info", foreground=self.colors['accent'], font=('Consolas', 11))
        self.results_text.tag_configure("success", foreground=self.colors['success'], font=('Consolas', 11, 'bold'))
        
    def create_network_discovery_tab(self):
        """Create network discovery tab"""
        discovery_frame = ttk.Frame(self.notebook)
        self.notebook.add(discovery_frame, text="🌐 Network Discovery")
        
        # Network range input
        range_frame = tk.LabelFrame(discovery_frame, text="Network Range", 
                                  font=('Arial', 12, 'bold'), bg='#2d2d2d', fg='#ffffff')
        range_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(range_frame, text="Network (e.g., 192.168.1.0/24):", 
                font=('Arial', 10), bg='#2d2d2d', fg='#ffffff').pack(anchor='w', padx=5, pady=5)
        
        self.network_var = tk.StringVar(value="192.168.1.0/24")
        network_entry = tk.Entry(range_frame, textvariable=self.network_var, 
                               font=('Arial', 10), width=50, bg='#3d3d3d', fg='#ffffff')
        network_entry.pack(padx=5, pady=(0, 5))
        
        # Discovery buttons
        discovery_buttons = tk.Frame(discovery_frame, bg='#2d2d2d')
        discovery_buttons.pack(fill='x', padx=10, pady=5)
        
        ping_button = tk.Button(discovery_buttons, text="🏓 Ping Sweep", 
                              command=self.ping_sweep, bg='#00d4aa', fg='#000000',
                              font=('Arial', 10, 'bold'), padx=20, pady=5)
        ping_button.pack(side='left', padx=5)
        
        arp_button = tk.Button(discovery_buttons, text="🔍 ARP Scan", 
                             command=self.arp_scan, bg='#4ecdc4', fg='#000000',
                             font=('Arial', 10, 'bold'), padx=20, pady=5)
        arp_button.pack(side='left', padx=5)
        
        # Discovery results
        discovery_results = scrolledtext.ScrolledText(
            discovery_frame, font=('Consolas', 10), bg='#0d1117', fg='#c9d1d9',
            height=20
        )
        discovery_results.pack(fill='both', expand=True, padx=10, pady=10)
        self.discovery_results = discovery_results
        
    def create_service_detection_tab(self):
        """Create service detection tab"""
        service_frame = ttk.Frame(self.notebook)
        self.notebook.add(service_frame, text="🔧 Service Detection")
        
        # Service detection controls
        service_controls = tk.LabelFrame(service_frame, text="Service Detection", 
                                       font=('Arial', 12, 'bold'), bg='#2d2d2d', fg='#ffffff')
        service_controls.pack(fill='x', padx=10, pady=10)
        
        tk.Label(service_controls, text="Target Host:", font=('Arial', 10), 
                bg='#2d2d2d', fg='#ffffff').pack(anchor='w', padx=5, pady=5)
        
        self.service_target_var = tk.StringVar()
        service_target_entry = tk.Entry(service_controls, textvariable=self.service_target_var,
                                      font=('Arial', 10), width=50, bg='#3d3d3d', fg='#ffffff')
        service_target_entry.pack(padx=5, pady=(0, 5))
        
        detect_button = tk.Button(service_controls, text="🔍 Detect Services", 
                                command=self.detect_services, bg='#00d4aa', fg='#000000',
                                font=('Arial', 10, 'bold'), padx=20, pady=5)
        detect_button.pack(padx=5, pady=5)
        
        # Service detection results
        service_results = scrolledtext.ScrolledText(
            service_frame, font=('Consolas', 10), bg='#0d1117', fg='#c9d1d9',
            height=20
        )
        service_results.pack(fill='both', expand=True, padx=10, pady=10)
        self.service_results = service_results
        
    def create_scan_history_tab(self):
        """Create scan history tab"""
        history_frame = ttk.Frame(self.notebook)
        self.notebook.add(history_frame, text="📚 Scan History")
        
        # History controls
        history_controls = tk.Frame(history_frame, bg='#2d2d2d')
        history_controls.pack(fill='x', padx=10, pady=10)
        
        clear_history_btn = tk.Button(history_controls, text="🗑️ Clear History", 
                                    command=self.clear_history, bg='#ff6b6b', fg='#ffffff',
                                    font=('Arial', 10), padx=15, pady=5)
        clear_history_btn.pack(side='left', padx=5)
        
        export_history_btn = tk.Button(history_controls, text="💾 Export History", 
                                     command=self.export_history, bg='#4ecdc4', fg='#000000',
                                     font=('Arial', 10), padx=15, pady=5)
        export_history_btn.pack(side='left', padx=5)
        
        # History list
        self.history_listbox = tk.Listbox(history_frame, font=('Arial', 10), 
                                        bg='#2d2d2d', fg='#ffffff', selectbackground='#00d4aa')
        self.history_listbox.pack(fill='both', expand=True, padx=10, pady=10)
        self.history_listbox.bind('<Double-Button-1>', self.load_history_item)
        
    def create_settings_tab(self):
        """Create settings tab"""
        settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(settings_frame, text="⚙️ Settings")
        
        # Appearance settings
        appearance_frame = tk.LabelFrame(settings_frame, text="Appearance", 
                                       font=('Arial', 12, 'bold'), bg='#2d2d2d', fg='#ffffff')
        appearance_frame.pack(fill='x', padx=10, pady=10)
        
        self.theme_var = tk.StringVar(value="Dark")
        theme_combo = ttk.Combobox(appearance_frame, textvariable=self.theme_var,
                                 values=["Dark", "Light", "High Contrast"], state="readonly")
        theme_combo.pack(padx=10, pady=10)
        
        # Scan settings
        scan_settings_frame = tk.LabelFrame(settings_frame, text="Default Scan Settings", 
                                          font=('Arial', 12, 'bold'), bg='#2d2d2d', fg='#ffffff')
        scan_settings_frame.pack(fill='x', padx=10, pady=10)
        
        # About section
        about_frame = tk.LabelFrame(settings_frame, text="About DuckScanner", 
                                  font=('Arial', 12, 'bold'), bg='#2d2d2d', fg='#ffffff')
        about_frame.pack(fill='x', padx=10, pady=10)
        
        about_text = """
🦆 DuckScanner v2.0
Advanced Network Scanner & Security Tool

Created by: Kirill Tikhomirov

Features:
• Multi-threaded port scanning
• Network discovery and ping sweeps
• Service detection and banner grabbing
• Scan history and export capabilities
• Modern GUI with dark theme
• Multiple scan types and presets
• Professional-grade security tools

Developed with Python & Tkinter
© 2024 Kirill Tikhomirov
        """
        
        tk.Label(about_frame, text=about_text, font=('Arial', 10), 
                bg='#2d2d2d', fg='#ffffff', justify='left').pack(padx=10, pady=10)
        
    def create_status_bar(self):
        """Create status bar"""
        self.status_var = tk.StringVar(value="🦆 Ready - DuckScanner by Kirill Tikhomirov")
        status_bar = tk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, 
                            anchor='w', bg=self.colors['bg_secondary'], fg=self.colors['text_primary'], 
                            font=('Segoe UI', 9, 'bold'), bd=2)
        status_bar.pack(side='bottom', fill='x')
        
    def set_ports(self, ports):
        """Set ports from preset"""
        self.ports_var.set(ports)
        
    def parse_ports(self, port_string):
        """Parse port string"""
        ports = []
        for part in port_string.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports
    
    def get_service_name(self, port):
        """Get service name for port"""
        return self.services.get(port, 'Unknown')
    
    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_var.get())
            result = sock.connect_ex((self.target_var.get(), port))
            sock.close()
            
            if result == 0:
                return port, True, self.get_service_name(port)
            else:
                return port, False, None
        except Exception as e:
            return port, False, f"Error: {str(e)}"
    
    def banner_grab(self, host, port):
        """Grab banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            sock.send(b'\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:100] if banner else "No banner"
        except:
            return "No banner"
    
    def update_results(self, port, is_open, service):
        """Update results display"""
        if is_open:
            banner = self.banner_grab(self.target_var.get(), port)
            result_text = f"✅ Port {port}/tcp open - {service}\n"
            if banner != "No banner":
                result_text += f"   Banner: {banner}\n"
            result_text += "\n"
            
            self.results_text.insert(tk.END, result_text, "open")
            self.results_text.see(tk.END)
            self.scan_results.append({
                'port': port,
                'state': 'open',
                'service': service,
                'banner': banner
            })
    
    def scan_worker(self):
        """Worker thread for scanning"""
        try:
            target = self.target_var.get()
            ports = self.parse_ports(self.ports_var.get())
            
            self.results_text.insert(tk.END, f"🦆 DuckScanner - Starting scan...\n", "info")
            self.results_text.insert(tk.END, f"Target: {target}\n", "info")
            self.results_text.insert(tk.END, f"Ports: {len(ports)}\n", "info")
            self.results_text.insert(tk.END, f"Threads: {self.threads_var.get()}\n", "info")
            self.results_text.insert(tk.END, f"Scan Type: {self.scan_type_var.get()}\n", "info")
            self.results_text.insert(tk.END, "-" * 50 + "\n\n", "info")
            
            start_time = time.time()
            open_count = 0
            
            with ThreadPoolExecutor(max_workers=self.threads_var.get()) as executor:
                futures = {executor.submit(self.scan_port, port): port for port in ports}
                
                for future in as_completed(futures):
                    if not self.is_scanning:
                        break
                        
                    port, is_open, service = future.result()
                    if is_open:
                        open_count += 1
                        self.root.after(0, self.update_results, port, is_open, service)
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.root.after(0, self.scan_completed, open_count, duration)
            
        except Exception as e:
            self.root.after(0, self.scan_error, str(e))
    
    def scan_completed(self, open_count, duration):
        """Called when scan is completed"""
        self.is_scanning = False
        self.scan_button.config(text="🚀 Start Scan", bg=self.colors['success'],
                               activebackground='#6dd47e')
        self.progress_bar.stop()
        
        self.results_text.insert(tk.END, "-" * 50 + "\n", "info")
        self.results_text.insert(tk.END, f"✅ Scan completed in {duration:.2f} seconds\n", "success")
        self.results_text.insert(tk.END, f"🔓 Open ports found: {open_count}\n\n", "success")
        
        self.progress_var.set(f"Scan completed - {open_count} open ports found")
        self.status_var.set(f"🦆 Scan completed in {duration:.2f}s - {open_count} open ports - DuckScanner by Kirill Tikhomirov")
        
        # Save to history
        self.save_scan_to_history(open_count, duration)
    
    def scan_error(self, error_msg):
        """Called when scan encounters an error"""
        self.is_scanning = False
        self.scan_button.config(text="🚀 Start Scan", bg=self.colors['success'],
                               activebackground='#6dd47e')
        self.progress_bar.stop()
        
        self.results_text.insert(tk.END, f"❌ Error: {error_msg}\n", "error")
        self.progress_var.set("Scan failed")
        self.status_var.set("🦆 Scan failed - DuckScanner by Kirill Tikhomirov")
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error_msg}")
    
    def start_scan(self):
        """Start the port scan"""
        if self.is_scanning:
            self.stop_scan()
            return
        
        if not self.target_var.get().strip():
            messagebox.showerror("Error", "Please enter a target IP address or hostname")
            return
        
        try:
            self.parse_ports(self.ports_var.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid port format. Use comma-separated ports or ranges (e.g., 80,443 or 1-1000)")
            return
        
        self.is_scanning = True
        self.scan_results = []
        self.scan_button.config(text="⏹️ Stop Scan", bg=self.colors['error'], 
                               activebackground='#ff4757')
        self.progress_bar.start()
        self.progress_var.set("Scanning in progress...")
        self.status_var.set("🦆 Scanning... - DuckScanner by Kirill Tikhomirov")
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.scan_worker, daemon=True)
        scan_thread.start()
    
    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False
        self.scan_button.config(text="🚀 Start Scan", bg=self.colors['success'],
                               activebackground='#6dd47e')
        self.progress_bar.stop()
        self.progress_var.set("Scan stopped")
        self.status_var.set("🦆 Scan stopped - DuckScanner by Kirill Tikhomirov")
    
    def clear_results(self):
        """Clear the results display"""
        self.results_text.delete(1.0, tk.END)
        self.scan_results = []
        self.progress_var.set("Ready to scan")
        self.status_var.set("🦆 Ready - DuckScanner by Kirill Tikhomirov")
    
    def export_results(self):
        """Export scan results"""
        if not self.scan_results:
            messagebox.showwarning("Warning", "No scan results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("Text files", "*.txt")]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(self.scan_results, f, indent=2)
                elif filename.endswith('.csv'):
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Port', 'State', 'Service', 'Banner'])
                        for result in self.scan_results:
                            writer.writerow([result['port'], result['state'], result['service'], result['banner']])
                else:
                    with open(filename, 'w') as f:
                        for result in self.scan_results:
                            f.write(f"Port {result['port']}/tcp open - {result['service']}\n")
                            if result['banner'] != "No banner":
                                f.write(f"Banner: {result['banner']}\n")
                            f.write("\n")
                
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {e}")
    
    def ping_sweep(self):
        """Perform ping sweep"""
        network = self.network_var.get()
        if not network:
            messagebox.showerror("Error", "Please enter a network range")
            return
        
        self.discovery_results.delete(1.0, tk.END)
        self.discovery_results.insert(tk.END, f"🏓 Starting ping sweep for {network}...\n")
        
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            hosts = list(network_obj.hosts())
            
            def ping_host(host):
                try:
                    if platform.system().lower() == "windows":
                        result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(host)], 
                                              capture_output=True, text=True, timeout=3)
                    else:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', str(host)], 
                                              capture_output=True, text=True, timeout=3)
                    return str(host), result.returncode == 0
                except:
                    return str(host), False
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(ping_host, host): host for host in hosts}
                
                for future in as_completed(futures):
                    host, is_alive = future.result()
                    if is_alive:
                        self.discovery_results.insert(tk.END, f"✅ {host} is alive\n")
                    else:
                        self.discovery_results.insert(tk.END, f"❌ {host} is not responding\n")
        
        except Exception as e:
            self.discovery_results.insert(tk.END, f"❌ Error: {e}\n")
    
    def arp_scan(self):
        """Perform ARP scan"""
        self.discovery_results.insert(tk.END, "🔍 ARP scan not implemented yet\n")
    
    def detect_services(self):
        """Detect services on target"""
        target = self.service_target_var.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target host")
            return
        
        self.service_results.delete(1.0, tk.END)
        self.service_results.insert(tk.END, f"🔧 Detecting services on {target}...\n")
        
        # Scan common ports
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        
        def check_service(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    service = self.get_service_name(port)
                    banner = self.banner_grab(target, port)
                    return port, service, banner
                return None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_service, port): port for port in common_ports}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    port, service, banner = result
                    self.service_results.insert(tk.END, f"✅ Port {port}/tcp - {service}\n")
                    if banner != "No banner":
                        self.service_results.insert(tk.END, f"   Banner: {banner}\n")
                    self.service_results.insert(tk.END, "\n")
    
    def save_scan_to_history(self, open_count, duration):
        """Save scan to history"""
        scan_info = {
            'timestamp': datetime.now().isoformat(),
            'target': self.target_var.get(),
            'ports': self.ports_var.get(),
            'open_ports': open_count,
            'duration': duration,
            'results': self.scan_results
        }
        self.scan_history.append(scan_info)
        self.update_history_display()
        self.save_scan_history()
    
    def update_history_display(self):
        """Update history display"""
        self.history_listbox.delete(0, tk.END)
        for i, scan in enumerate(self.scan_history):
            timestamp = datetime.fromisoformat(scan['timestamp']).strftime("%Y-%m-%d %H:%M:%S")
            self.history_listbox.insert(tk.END, f"{timestamp} - {scan['target']} ({scan['open_ports']} open ports)")
    
    def load_history_item(self, event):
        """Load selected history item"""
        selection = self.history_listbox.curselection()
        if selection:
            scan = self.scan_history[selection[0]]
            self.target_var.set(scan['target'])
            self.ports_var.set(scan['ports'])
            self.scan_results = scan['results']
            
            # Switch to port scanner tab
            self.notebook.select(0)
            self.clear_results()
            
            # Display results
            for result in scan['results']:
                self.results_text.insert(tk.END, f"✅ Port {result['port']}/tcp open - {result['service']}\n")
                if result['banner'] != "No banner":
                    self.results_text.insert(tk.END, f"   Banner: {result['banner']}\n")
                self.results_text.insert(tk.END, "\n")
    
    def clear_history(self):
        """Clear scan history"""
        self.scan_history = []
        self.update_history_display()
        self.save_scan_history()
    
    def export_history(self):
        """Export scan history"""
        if not self.scan_history:
            messagebox.showwarning("Warning", "No scan history to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(self.scan_history, f, indent=2)
                else:
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Timestamp', 'Target', 'Ports', 'Open Ports', 'Duration'])
                        for scan in self.scan_history:
                            writer.writerow([
                                scan['timestamp'],
                                scan['target'],
                                scan['ports'],
                                scan['open_ports'],
                                scan['duration']
                            ])
                
                messagebox.showinfo("Success", f"History exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export history: {e}")
    
    def save_scan_history(self):
        """Save scan history to file"""
        try:
            with open('scan_history.json', 'w') as f:
                json.dump(self.scan_history, f, indent=2)
        except Exception:
            pass
    
    def load_scan_history(self):
        """Load scan history from file"""
        try:
            if os.path.exists('scan_history.json'):
                with open('scan_history.json', 'r') as f:
                    self.scan_history = json.load(f)
                self.update_history_display()
        except Exception:
            pass

def main():
    root = tk.Tk()
    app = DuckScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()
