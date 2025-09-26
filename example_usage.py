#!/usr/bin/env python3
"""
Example usage of the port scanner
"""

import subprocess
import sys

def run_example():
    """Run example port scans"""
    
    print("Port Scanner Examples")
    print("=" * 30)
    
    examples = [
        {
            "description": "Scan localhost on common ports",
            "command": ["python", "port_scanner.py", "127.0.0.1", "-p", "22,80,443,8080"]
        },
        {
            "description": "Scan a specific host with port range",
            "command": ["python", "port_scanner.py", "192.168.1.1", "-p", "1-100", "-t", "20"]
        },
        {
            "description": "Show help",
            "command": ["python", "port_scanner.py", "--help"]
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n{i}. {example['description']}")
        print(f"   Command: {' '.join(example['command'])}")
        print("-" * 40)
        
        try:
            result = subprocess.run(example['command'], 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=10)
            
            if result.returncode == 0:
                print("✅ Success!")
                if result.stdout:
                    print("Output:")
                    print(result.stdout)
            else:
                print("❌ Failed!")
                if result.stderr:
                    print("Error:", result.stderr)
                    
        except subprocess.TimeoutExpired:
            print("⏰ Timeout!")
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    run_example()
