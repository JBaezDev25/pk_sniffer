# Packet Sniffer Monitor - Network Security Tool

A powerful network packet sniffer and threat detection tool written in C for Linux environments. This tool captures and analyzes network traffic in real-time, detecting potential security threats such as port scans, suspicious connections, and malicious packet patterns.

## Features

- **Real-time Packet Capture**: Monitors network traffic using libpcap library
- **Threat Detection**:
  - Port scanning detection (SYN, NULL, XMAS scans)
  - Suspicious port monitoring (common attack vectors)
  - ICMP flood detection
  - Oversized packet detection
  - Malformed packet identification
- **Protocol Support**: TCP, UDP, ICMP analysis
- **Color-coded Alerts**: Easy-to-read terminal output with threat highlighting
- **Statistics Tracking**: Comprehensive packet and threat statistics
- **Configurable**: Monitor specific network interfaces

## Security Threats Detected

1. **Port Scans**:
   - SYN scan detection
   - NULL scan detection
   - XMAS scan detection
   - Automated port scan threshold alerts

2. **Suspicious Ports**:
   - FTP (21), Telnet (23)
   - SMB (445), RDP (3389)
   - MySQL (3306), MS SQL (1433)
   - VNC (5900), IRC (6667)
   - Known trojan ports (31337, 12345)

3. **Attack Patterns**:
   - ICMP flood attempts
   - Oversized packets (potential buffer overflow)
   - Unusual protocol usage

## Prerequisites

### Required Packages

Install libpcap development library:

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install libpcap-dev build-essential

# Fedora/RHEL/CentOS
sudo dnf install libpcap-devel gcc make

# Arch Linux
sudo pacman -S libpcap base-devel
```

### Permissions

This tool requires **root privileges** to capture network packets. Always run with `sudo`.

## Installation

### Quick Install

```bash
# Clone or navigate to the repository
cd al4nbr3

# Compile the program
make

# Run the sniffer
sudo ./packet_sniffer
```

### System-wide Installation

```bash
# Build and install to /usr/local/bin
make
sudo make install

# Now you can run from anywhere
sudo packet_sniffer
```

## Usage

### Basic Usage

```bash
# Monitor default network interface
sudo ./packet_sniffer

# Monitor specific interface
sudo ./packet_sniffer eth0
sudo ./packet_sniffer wlan0
```

### Finding Your Network Interface

```bash
# List all network interfaces
ip link show

# Or use ifconfig
ifconfig -a
```

### Stop Monitoring

Press `Ctrl+C` to stop packet capture and display statistics.

## Output Example

```
╔═══════════════════════════════════════════════════════╗
║     Packet Sniffer Monitor - Security Tool v1.0      ║
║     Network Threat Detection & Monitoring            ║
╚═══════════════════════════════════════════════════════╝

[INFO] Monitoring device: eth0
[INFO] Packet capture started. Press Ctrl+C to stop.
[INFO] Monitoring for potential threats...

[THREAT ALERT] [2026-01-20 14:23:45] PORT_SCAN: Port scan detected from 192.168.1.100 (15 ports in 8 seconds)
[THREAT ALERT] [2026-01-20 14:23:47] SUSPICIOUS_PORT: TCP traffic to suspicious port 3389 from 192.168.1.50 to 192.168.1.10
[STATS] Packets: 100 | Threats: 2 | TCP: 85 | UDP: 10 | ICMP: 5

=== Packet Capture Statistics ===
Total Packets:   1247
TCP Packets:     1053
UDP Packets:     142
ICMP Packets:    52
Other Packets:   0
Threat Alerts:   8
=================================
```

## Recommended IDEs for C Development on Linux

### 1. Visual Studio Code (VSCode) - **BEST OVERALL**

**Pros**:
- Free and open-source
- Excellent C/C++ extension support
- Integrated debugging with GDB
- Git integration
- Terminal built-in
- Cross-platform

**Setup**:
```bash
# Install VSCode
sudo snap install code --classic

# Or download from: https://code.visualstudio.com/

# Install C/C++ extension
# Open VSCode -> Extensions -> Search "C/C++" -> Install Microsoft C/C++
```

**Recommended Extensions**:
- C/C++ (Microsoft)
- C/C++ Extension Pack
- Code Runner
- GitLens
- Makefile Tools

### 2. CLion - **BEST PROFESSIONAL IDE**

**Pros**:
- Powerful code analysis
- Advanced refactoring
- Integrated CMake/Makefile support
- Smart code completion
- Built-in debugger and profiler

**Cons**:
- Paid (free for students/open-source projects)

**Setup**:
```bash
# Download from: https://www.jetbrains.com/clion/
# Or install via snap
sudo snap install clion --classic
```

### 3. Vim/Neovim - **BEST FOR TERMINAL**

**Pros**:
- Lightweight and fast
- Available on all Linux systems
- Highly customizable
- Great for remote development

**Setup**:
```bash
# Install Neovim
sudo apt-get install neovim

# Or build from source for latest version
# Add plugins for C development: coc.nvim, ale, youcompleteme
```

### 4. Code::Blocks - **BEST FOR BEGINNERS**

**Pros**:
- Free and open-source
- Easy to use
- Built-in compiler support
- Good for learning

**Setup**:
```bash
sudo apt-get install codeblocks
```

### 5. Eclipse CDT - **BEST FOR LARGE PROJECTS**

**Pros**:
- Free and mature
- Excellent project management
- Advanced debugging features
- Good for enterprise development

**Setup**:
```bash
sudo snap install eclipse --classic
# Or download from: https://www.eclipse.org/cdt/
```

## Development Tools

### Debugging

```bash
# Compile with debug symbols
gcc -g -Wall -o packet_sniffer packet_sniffer.c -lpcap

# Debug with GDB
sudo gdb ./packet_sniffer
```

### Code Analysis

```bash
# Static analysis with cppcheck
sudo apt-get install cppcheck
cppcheck packet_sniffer.c

# Memory leak detection with Valgrind
sudo apt-get install valgrind
sudo valgrind --leak-check=full ./packet_sniffer
```

### Code Formatting

```bash
# Install clang-format
sudo apt-get install clang-format

# Format code
clang-format -i packet_sniffer.c
```

## Configuration

### Customizing Suspicious Ports

Edit the `suspicious_ports[]` array in `packet_sniffer.c`:

```c
int suspicious_ports[] = {
    21,    // FTP
    23,    // Telnet
    // Add your custom ports here
    8080,  // HTTP Proxy
    0      // Keep this terminator
};
```

### Adjusting Detection Thresholds

Modify these constants in `packet_sniffer.c`:

```c
#define SUSPICIOUS_PACKET_SIZE 1400  // Packet size threshold
#define PORT_SCAN_THRESHOLD 10       // Number of ports before alert
#define TIME_WINDOW 60               // Time window in seconds
```

## Troubleshooting

### "Couldn't find default device"

```bash
# Check available interfaces
ip link show

# Specify interface explicitly
sudo ./packet_sniffer eth0
```

### "Operation not permitted"

```bash
# Ensure you're running with sudo
sudo ./packet_sniffer

# Check pcap permissions
ls -l /usr/bin/dumpcap
```

### No packets captured

```bash
# Check if interface is up
ip link set eth0 up

# Verify interface has traffic
tcpdump -i eth0 -c 10
```

## Project Structure

```
al4nbr3/
├── packet_sniffer.c    # Main source code
├── Makefile            # Build configuration
└── README.md           # This file
```

## Building from Source

```bash
# Manual compilation
gcc -Wall -Wextra -O2 -std=c11 -o packet_sniffer packet_sniffer.c -lpcap

# Using Makefile (recommended)
make

# Clean build
make clean
make
```

## Performance Tips

1. **Use specific interfaces**: Monitoring specific interfaces reduces overhead
2. **Filter traffic**: Consider adding BPF filters for specific traffic analysis
3. **Adjust buffer size**: Modify BUFSIZ in `pcap_open_live()` for high-traffic networks
4. **Disable color output**: Comment out COLOR_* codes for better performance

## Security Considerations

- **Legal Use Only**: Only monitor networks you own or have permission to monitor
- **Privacy**: This tool captures network traffic - ensure compliance with privacy laws
- **Root Access**: Run only when needed, avoid leaving running unattended
- **False Positives**: Legitimate traffic may trigger alerts - verify before taking action

## Future Enhancements

- [ ] Add packet filtering with BPF expressions
- [ ] Export alerts to log files
- [ ] Web dashboard for remote monitoring
- [ ] Machine learning-based threat detection
- [ ] Support for wireless monitoring (monitor mode)
- [ ] GeoIP lookup for source addresses
- [ ] Integration with IDS/IPS systems

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## Disclaimer

This tool is for educational and authorized security testing purposes only. The authors are not responsible for misuse or damage caused by this program. Always ensure you have proper authorization before monitoring network traffic.

## Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review libpcap documentation: https://www.tcpdump.org/

## References

- libpcap Documentation: https://www.tcpdump.org/manpages/pcap.3pcap.html
- TCP/IP Protocol Suite: https://www.ietf.org/rfc/
- Network Security Best Practices: https://www.sans.org/

---

**Built with ❤️ for network security monitoring**
