# 🦆 DuckScanner - Advanced Network Scanner

[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GUI](https://img.shields.io/badge/GUI-Tkinter-orange.svg)](https://docs.python.org/3/library/tkinter.html)

A comprehensive network scanning tool with a modern GUI interface, designed for security professionals, network administrators, and penetration testers.

## ✨ Features

### 🔍 **Port Scanning**
- **Multi-threaded scanning** with configurable thread count (1-500)
- **Multiple scan types**: TCP Connect, TCP SYN, UDP, Stealth
- **Port range support**: Individual ports, ranges (1-1000), or all ports (1-65535)
- **Real-time results** with color-coded output
- **Service detection** for 20+ common services
- **Banner grabbing** for open ports

### 🌐 **Network Discovery**
- **Ping sweep** for network range discovery
- **ARP scanning** (planned feature)
- **Host discovery** with customizable timeouts
- **Network range parsing** (CIDR notation support)

### 🔧 **Service Detection**
- **Automated service identification** for common ports
- **Banner grabbing** and service fingerprinting
- **Custom port scanning** for specific services
- **Service database** with 20+ predefined services

### 📚 **Scan Management**
- **Scan history** with timestamp and results
- **Export capabilities** (JSON, CSV, TXT formats)
- **Quick presets** for common scan types
- **Load previous scans** from history

### 🎨 **Modern Interface**
- **Dark theme** with professional appearance
- **Tabbed interface** for organized functionality
- **Real-time progress** indicators
- **Color-coded results** for easy interpretation
- **Responsive design** with scrollable results


## 🖼️ Screenshots

### Main Interface
![DuckScanner Main Interface](https://cdn.discordapp.com/attachments/1134142081250627684/1421077071865712662/image.png?ex=68d7b8a8&is=68d66728&hm=6f8df4b82263802e941ce5ec718e8c14bcd374551bc07d1fe8e053b7294794d8&)
*Modern dark-themed interface with professional design*




## 🚀 Quick Start

### Prerequisites
- Python 3.6 or higher
- No external dependencies required (uses only standard library)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/kirilt2/-DuckScanner---Advanced-Network-Scanner.git
   cd DuckScanner
   cd *
   ```

2. **Install Dependencies**
  ``` bash
  pip install -r requirements.txt
  ```
3. **Run the application**
   ```bash
   python DuckScanner.py
   ```

   Or on Windows:
   ```bash
   run_app.bat
   ```

### First Scan

1. **Enter target**: Type an IP address or hostname (e.g., `192.168.1.1`)
2. **Select ports**: Use presets or enter custom ports (e.g., `80,443,22` or `1-1000`)
3. **Configure settings**: Adjust threads and timeout if needed
4. **Start scan**: Click "🚀 Start Scan"
5. **View results**: Open ports appear in real-time with service information

## 📖 Usage Guide

### Port Scanner Tab

**Basic Configuration:**
- **Target**: IP address, hostname, or domain name
- **Ports**: Comma-separated ports or ranges (e.g., `22,80,443` or `1-1000`)
- **Scan Type**: Choose from TCP Connect, TCP SYN, UDP, or Stealth
- **Threads**: Number of concurrent connections (1-500)
- **Timeout**: Connection timeout in seconds (0.1-10.0)

**Quick Presets:**
- **Common Ports**: 22,23,25,53,80,110,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080
- **Web Ports**: 80,443,8080,8443,8000,8008,8081,9080,9443
- **Database Ports**: 1433,1521,3306,5432,6379,27017,9200
- **All Ports**: 1-65535 (use with caution!)

### Network Discovery Tab

**Ping Sweep:**
- Enter network range (e.g., `192.168.1.0/24`)
- Click "🏓 Ping Sweep" to discover live hosts
- Results show which hosts are responding

**ARP Scan:**
- Planned feature for local network discovery
- Will show MAC addresses and hostnames

### Service Detection Tab

**Service Detection:**
- Enter target host
- Click "🔍 Detect Services" to scan common ports
- Shows open ports with service names and banners

### Scan History Tab

**History Management:**
- View all previous scans with timestamps
- Double-click to load previous scan results
- Export history to JSON or CSV
- Clear history when needed

### Settings Tab

**Appearance:**
- Choose theme (Dark, Light, High Contrast)
- Customize default scan settings

**About:**
- Version information and feature list

## 🛠️ Advanced Usage

### Command Line Interface

For automated scanning, you can also use the command-line version:

```bash
python port_scanner.py 192.168.1.1 -p 80,443,22 -t 100 --timeout 2.0
```

### Export Results

**Supported Formats:**
- **JSON**: Complete scan data with metadata
- **CSV**: Tabular format for spreadsheet analysis
- **TXT**: Human-readable text format

**Export Options:**
- Export current scan results
- Export entire scan history
- Choose format based on your needs

### Performance Tuning

**Thread Count:**
- **Local networks**: 100-200 threads
- **Remote networks**: 20-50 threads
- **Slow connections**: 10-20 threads

**Timeout Settings:**
- **Local networks**: 0.5-1.0 seconds
- **Remote networks**: 2.0-5.0 seconds
- **Slow connections**: 5.0-10.0 seconds

## 🔧 Technical Details

### Architecture
- **GUI Framework**: Tkinter with custom styling
- **Threading**: Concurrent.futures for parallel scanning
- **Network**: Socket programming for port scanning
- **Data Storage**: JSON for scan history
- **Export**: Built-in JSON, CSV, and TXT support

### Service Database
The scanner includes a comprehensive service database with common ports:

| Port | Service | Port | Service |
|------|---------|------|---------|
| 21 | FTP | 443 | HTTPS |
| 22 | SSH | 993 | IMAPS |
| 23 | Telnet | 995 | POP3S |
| 25 | SMTP | 1723 | PPTP |
| 53 | DNS | 3306 | MySQL |
| 80 | HTTP | 3389 | RDP |
| 110 | POP3 | 5432 | PostgreSQL |
| 135 | RPC | 5900 | VNC |
| 139 | NetBIOS | 8080 | HTTP-Alt |

### Security Considerations

⚠️ **Important Security Notice:**
- Only scan networks you own or have explicit permission to scan
- Unauthorized scanning may violate laws and terms of service
- Use responsibly and in accordance with applicable regulations
- Consider the impact on target systems and networks

## 📁 Project Structure

```
DuckScanner/
├── DuckScanner.py          # Main GUI application
├── port_scanner.py         # Command-line version
├── example_usage.py        # Usage examples
├── run_app.bat            # Windows launcher
├── requirements.txt       # Dependencies
├── README.md             # This file
├── LICENSE               # MIT License
├── .gitignore           # Git ignore rules
└── scan_history.json    # Scan history (created on first run)
```

## 🤝 Contributing

We welcome contributions! Please feel free to submit:

- **Bug reports** and feature requests
- **Code improvements** and optimizations
- **New features** and functionality
- **Documentation** improvements
- **UI/UX enhancements**

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Python Community** for excellent standard library
- **Tkinter** for the GUI framework
- **Security Community** for inspiration and feedback
- **Open Source** contributors who make tools like this possible

## 🔮 Roadmap

### Planned Features
- [ ] **UDP scanning** implementation
- [ ] **SYN scanning** with raw sockets
- [ ] **OS detection** and fingerprinting
- [ ] **Vulnerability scanning** integration
- [ ] **Report generation** with templates
- [ ] **Plugin system** for custom modules
- [ ] **Database integration** for scan storage
- [ ] **API interface** for automation
- [ ] **Multi-platform** installers
- [ ] **Cloud scanning** capabilities

### Version History
- **v2.0** - Complete GUI rewrite with modern interface
- **v1.0** - Initial command-line version

---

**Happy Scanning! 🦆**

*DuckScanner - Making network security accessible and efficient*


## 📜 License

This project is licensed under the [MIT License](LICENSE).

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

© 2024 Kirill Tikhomirov  




