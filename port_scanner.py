#!/usr/bin/env python3
"""
Basic Port Scanner
A simple Python port scanner for network reconnaissance
"""

import socket
import threading
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScanner:
    def __init__(self, target, ports, threads=50, timeout=1):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.open_ports = []
        self.lock = threading.Lock()
    
    def scan_port(self, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                return port, True
            else:
                return port, False
        except Exception:
            return port, False
    
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
    
    def scan(self):
        """Perform the port scan"""
        print(f"Scanning {self.target}...")
        print(f"Ports: {len(self.ports)}")
        print(f"Threads: {self.threads}")
        print("-" * 40)
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, port): port for port in self.ports}
            
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    service = self.get_service_name(port)
                    print(f"Port {port}/tcp open - {service}")
        
        end_time = time.time()
        duration = end_time - start_time
        
        print("-" * 40)
        print(f"Scan completed in {duration:.2f} seconds")
        print(f"Open ports found: {len(self.open_ports)}")
        
        if self.open_ports:
            print("\nOpen ports:")
            for port in sorted(self.open_ports):
                service = self.get_service_name(port)
                print(f"  {port}/tcp - {service}")

def parse_ports(port_string):
    """Parse port string (e.g., '80,443,22' or '1-1000')"""
    ports = []
    
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return ports

def main():
    parser = argparse.ArgumentParser(description='Basic Port Scanner')
    parser.add_argument('target', help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', default='1-1000', 
                       help='Ports to scan (default: 1-1000)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=float, default=1.0,
                       help='Connection timeout in seconds (default: 1.0)')
    
    args = parser.parse_args()
    
    try:
        # Parse ports
        ports = parse_ports(args.ports)
        
        # Create and run scanner
        scanner = PortScanner(args.target, ports, args.threads, args.timeout)
        scanner.scan()
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
