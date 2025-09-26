#!/usr/bin/env python3
"""
Port Scanner GUI Application
A simple desktop app for network port scanning
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner App")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Variables
        self.target_var = tk.StringVar()
        self.ports_var = tk.StringVar(value="1-1000")
        self.threads_var = tk.IntVar(value=50)
        self.timeout_var = tk.DoubleVar(value=1.0)
        self.is_scanning = False
        self.open_ports = []
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the user interface"""
        # Title
        title_label = tk.Label(
            self.root, 
            text="🔍 Port Scanner", 
            font=("Arial", 20, "bold"),
            bg='#f0f0f0',
            fg='#2c3e50'
        )
        title_label.pack(pady=10)
        
        # Main frame
        main_frame = tk.Frame(self.root, bg='#f0f0f0')
        main_frame.pack(padx=20, pady=10, fill='both', expand=True)
        
        # Input section
        input_frame = tk.LabelFrame(main_frame, text="Scan Configuration", font=("Arial", 12, "bold"), bg='#f0f0f0')
        input_frame.pack(fill='x', pady=(0, 10))
        
        # Target input
        tk.Label(input_frame, text="Target IP/Hostname:", font=("Arial", 10), bg='#f0f0f0').grid(row=0, column=0, sticky='w', padx=5, pady=5)
        target_entry = tk.Entry(input_frame, textvariable=self.target_var, font=("Arial", 10), width=30)
        target_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        
        # Ports input
        tk.Label(input_frame, text="Ports (e.g., 80,443 or 1-1000):", font=("Arial", 10), bg='#f0f0f0').grid(row=1, column=0, sticky='w', padx=5, pady=5)
        ports_entry = tk.Entry(input_frame, textvariable=self.ports_var, font=("Arial", 10), width=30)
        ports_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')
        
        # Threads input
        tk.Label(input_frame, text="Threads:", font=("Arial", 10), bg='#f0f0f0').grid(row=2, column=0, sticky='w', padx=5, pady=5)
        threads_spinbox = tk.Spinbox(input_frame, from_=1, to=200, textvariable=self.threads_var, font=("Arial", 10), width=10)
        threads_spinbox.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        # Timeout input
        tk.Label(input_frame, text="Timeout (seconds):", font=("Arial", 10), bg='#f0f0f0').grid(row=3, column=0, sticky='w', padx=5, pady=5)
        timeout_spinbox = tk.Spinbox(input_frame, from_=0.1, to=10.0, increment=0.1, textvariable=self.timeout_var, font=("Arial", 10), width=10)
        timeout_spinbox.grid(row=3, column=1, padx=5, pady=5, sticky='w')
        
        # Configure grid weights
        input_frame.columnconfigure(1, weight=1)
        
        # Button frame
        button_frame = tk.Frame(main_frame, bg='#f0f0f0')
        button_frame.pack(fill='x', pady=10)
        
        # Scan button
        self.scan_button = tk.Button(
            button_frame, 
            text="Start Scan", 
            command=self.start_scan,
            font=("Arial", 12, "bold"),
            bg='#3498db',
            fg='white',
            padx=20,
            pady=5
        )
        self.scan_button.pack(side='left', padx=5)
        
        # Clear button
        clear_button = tk.Button(
            button_frame, 
            text="Clear Results", 
            command=self.clear_results,
            font=("Arial", 12),
            bg='#95a5a6',
            fg='white',
            padx=20,
            pady=5
        )
        clear_button.pack(side='left', padx=5)
        
        # Progress bar
        self.progress_var = tk.StringVar(value="Ready to scan")
        progress_label = tk.Label(main_frame, textvariable=self.progress_var, font=("Arial", 10), bg='#f0f0f0', fg='#7f8c8d')
        progress_label.pack(pady=5)
        
        self.progress_bar = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress_bar.pack(fill='x', pady=5)
        
        # Results section
        results_frame = tk.LabelFrame(main_frame, text="Scan Results", font=("Arial", 12, "bold"), bg='#f0f0f0')
        results_frame.pack(fill='both', expand=True, pady=(10, 0))
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(
            results_frame, 
            font=("Consolas", 10),
            bg='#2c3e50',
            fg='#ecf0f1',
            insertbackground='white'
        )
        self.results_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w', bg='#34495e', fg='white')
        status_bar.pack(side='bottom', fill='x')
        
    def parse_ports(self, port_string):
        """Parse port string (e.g., '80,443,22' or '1-1000')"""
        ports = []
        
        for part in port_string.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        
        return ports
    
    def get_service_name(self, port):
        """Get service name for common ports"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 1723: 'PPTP',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')
    
    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout_var.get())
            result = sock.connect_ex((self.target_var.get(), port))
            sock.close()
            
            if result == 0:
                return port, True
            else:
                return port, False
        except Exception:
            return port, False
    
    def update_results(self, port, is_open):
        """Update results display"""
        if is_open:
            service = self.get_service_name(port)
            result_text = f"✅ Port {port}/tcp open - {service}\n"
            self.results_text.insert(tk.END, result_text)
            self.results_text.see(tk.END)
            self.open_ports.append(port)
    
    def scan_worker(self):
        """Worker thread for scanning"""
        try:
            target = self.target_var.get()
            ports = self.parse_ports(self.ports_var.get())
            
            self.results_text.insert(tk.END, f"🔍 Scanning {target}...\n")
            self.results_text.insert(tk.END, f"📊 Ports to scan: {len(ports)}\n")
            self.results_text.insert(tk.END, f"🧵 Threads: {self.threads_var.get()}\n")
            self.results_text.insert(tk.END, "-" * 50 + "\n")
            
            start_time = time.time()
            open_count = 0
            
            with ThreadPoolExecutor(max_workers=self.threads_var.get()) as executor:
                futures = {executor.submit(self.scan_port, port): port for port in ports}
                
                for future in as_completed(futures):
                    if not self.is_scanning:
                        break
                        
                    port, is_open = future.result()
                    if is_open:
                        open_count += 1
                        self.root.after(0, self.update_results, port, is_open)
            
            end_time = time.time()
            duration = end_time - start_time
            
            self.root.after(0, self.scan_completed, open_count, duration)
            
        except Exception as e:
            self.root.after(0, self.scan_error, str(e))
    
    def scan_completed(self, open_count, duration):
        """Called when scan is completed"""
        self.is_scanning = False
        self.scan_button.config(text="Start Scan", bg='#3498db')
        self.progress_bar.stop()
        
        self.results_text.insert(tk.END, "-" * 50 + "\n")
        self.results_text.insert(tk.END, f"✅ Scan completed in {duration:.2f} seconds\n")
        self.results_text.insert(tk.END, f"🔓 Open ports found: {open_count}\n")
        
        self.progress_var.set(f"Scan completed - {open_count} open ports found")
        self.status_var.set(f"Scan completed in {duration:.2f}s - {open_count} open ports")
    
    def scan_error(self, error_msg):
        """Called when scan encounters an error"""
        self.is_scanning = False
        self.scan_button.config(text="Start Scan", bg='#3498db')
        self.progress_bar.stop()
        
        self.results_text.insert(tk.END, f"❌ Error: {error_msg}\n")
        self.progress_var.set("Scan failed")
        self.status_var.set("Scan failed")
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
        self.open_ports = []
        self.scan_button.config(text="Stop Scan", bg='#e74c3c')
        self.progress_bar.start()
        self.progress_var.set("Scanning in progress...")
        self.status_var.set("Scanning...")
        
        # Start scan in separate thread
        scan_thread = threading.Thread(target=self.scan_worker, daemon=True)
        scan_thread.start()
    
    def stop_scan(self):
        """Stop the current scan"""
        self.is_scanning = False
        self.scan_button.config(text="Start Scan", bg='#3498db')
        self.progress_bar.stop()
        self.progress_var.set("Scan stopped")
        self.status_var.set("Scan stopped")
    
    def clear_results(self):
        """Clear the results display"""
        self.results_text.delete(1.0, tk.END)
        self.open_ports = []
        self.progress_var.set("Ready to scan")
        self.status_var.set("Ready")

def main():
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
