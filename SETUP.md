# Quick Start Guide - Packet Sniffer Monitor

## What Changed - Standard C Compliance

✅ **FIXED**: The code now uses **standard C types** instead of BSD-style types:
- `u_int` → `uint32_t` (standard C)
- `u_char` → `unsigned char` (standard C)
- `u_short` → `unsigned short` (standard C)
- TCP/UDP headers now use POSIX-compliant field names (`th_sport`/`th_dport` for TCP, `uh_sport`/`uh_dport` for UDP)

## Installation Steps (Run These Commands)

### 1. Install Dependencies

```bash
# Navigate to project directory
cd ~/development/al4nbr3

# Install required libraries
sudo apt-get update
sudo apt-get install libpcap-dev build-essential -y
```

### 2. Compile the Program

```bash
# Clean any old builds
make clean

# Compile the packet sniffer
make
```

**Expected output:**
```
Compiling packet_sniffer...
gcc -Wall -Wextra -O2 -std=c11 -o packet_sniffer packet_sniffer.c -lpcap
✓ Compilation successful!
Build complete! Run with: sudo ./packet_sniffer
```

### 3. Find Your Network Interface

```bash
# List all network interfaces
ip link show

# Common interface names:
# - eth0, enp0s3, eno1 (Ethernet)
# - wlan0, wlp2s0, wlo1 (WiFi)
# - lo (loopback - DON'T use this one)
```

### 4. Run the Packet Sniffer

```bash
# Run with auto-detected interface
sudo ./packet_sniffer

# OR specify your interface (replace 'eth0' with your actual interface)
sudo ./packet_sniffer eth0

# Stop with: Ctrl+C
```

## Expected Output

```
╔═══════════════════════════════════════════════════════╗
║     Packet Sniffer Monitor - Security Tool v1.0      ║
║     Network Threat Detection & Monitoring            ║
╚═══════════════════════════════════════════════════════╝

[INFO] Monitoring device: eth0
[INFO] Packet capture started. Press Ctrl+C to stop.
[INFO] Monitoring for potential threats...

[STATS] Packets: 100 | Threats: 0 | TCP: 85 | UDP: 10 | ICMP: 5
[THREAT ALERT] [2026-01-20 15:23:45] SUSPICIOUS_PORT: TCP traffic to port 3389
[THREAT ALERT] [2026-01-20 15:24:12] PORT_SCAN: Port scan from 203.0.113.100

=== Packet Capture Statistics ===
Total Packets:   547
TCP Packets:     423
UDP Packets:     98
ICMP Packets:    26
Other Packets:   0
Threat Alerts:   2
=================================
```

## Troubleshooting

### Error: "pcap.h: No such file or directory"
**Solution**: Install libpcap-dev
```bash
sudo apt-get install libpcap-dev
```

### Error: "This program requires root privileges"
**Solution**: Use sudo
```bash
sudo ./packet_sniffer
```

### Error: "Couldn't find default device"
**Solution**: Specify interface explicitly
```bash
# Find your interface
ip link show

# Use it
sudo ./packet_sniffer eth0
```

### Error: "Couldn't open device: Permission denied"
**Solution**: Make sure you're using sudo
```bash
sudo ./packet_sniffer eth0
```

### No packets captured
**Solution**: Check if interface is up and has traffic
```bash
# Bring interface up
sudo ip link set eth0 up

# Generate some traffic (in another terminal)
ping google.com

# Or run a web browser to generate traffic
```

## IDE Setup - Visual Studio Code (Recommended)

### Install VSCode

```bash
# Method 1: Using snap (recommended)
sudo snap install code --classic

# Method 2: Using apt (alternative)
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
sudo apt update
sudo apt install code
```

### Open Project in VSCode

```bash
cd ~/development/al4nbr3
code .
```

### Install C/C++ Extension

1. Open VSCode
2. Click Extensions icon (left sidebar) or press `Ctrl+Shift+X`
3. Search for "C/C++"
4. Install **"C/C++"** by Microsoft
5. Install **"C/C++ Extension Pack"** (optional but recommended)

### Build and Debug in VSCode

**Build with keyboard shortcut:**
- Press `Ctrl+Shift+B` to build
- Select "make" or create a task

**Create `.vscode/tasks.json`:**
```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Build Packet Sniffer",
            "type": "shell",
            "command": "make",
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "problemMatcher": ["$gcc"]
        },
        {
            "label": "Clean",
            "type": "shell",
            "command": "make clean"
        }
    ]
}
```

**Create `.vscode/launch.json` for debugging:**
```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug Packet Sniffer",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/packet_sniffer",
            "args": ["eth0"],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}",
            "environment": [],
            "externalConsole": false,
            "MIMode": "gdb",
            "sudo": true,
            "setupCommands": [
                {
                    "description": "Enable pretty-printing for gdb",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                }
            ],
            "preLaunchTask": "Build Packet Sniffer"
        }
    ]
}
```

## Alternative IDEs

### CLion (Professional)
```bash
sudo snap install clion --classic
# Open project: File > Open > ~/development/al4nbr3
```

### Code::Blocks (Beginner-Friendly)
```bash
sudo apt install codeblocks
codeblocks ~/development/al4nbr3/packet_sniffer.c
```

### Vim/Neovim (Terminal-Based)
```bash
sudo apt install neovim
nvim ~/development/al4nbr3/packet_sniffer.c
```

## Features & Threat Detection

### What the Program Detects:

| Threat Type | Description |
|------------|-------------|
| **PORT_SCAN** | Multiple SYN packets to different ports (default: 10+ ports in 60 seconds) |
| **SUSPICIOUS_PORT** | Traffic to/from dangerous ports (FTP, Telnet, RDP, SMB, etc.) |
| **NULL_SCAN** | TCP packets with all flags set to 0 (stealth scan technique) |
| **XMAS_SCAN** | TCP packets with FIN+PSH+URG flags (stealth scan technique) |
| **ICMP_FLOOD** | Excessive ICMP traffic (100+ packets in 10 seconds) |
| **SUSPICIOUS_SIZE** | Packets larger than 1400 bytes |

### Suspicious Ports Monitored:

- **21** - FTP (File Transfer Protocol)
- **23** - Telnet (Unencrypted remote access)
- **135** - MS RPC (Windows vulnerability vector)
- **139** - NetBIOS (Windows file sharing)
- **445** - SMB (Common ransomware target)
- **1433** - MS SQL Server
- **3306** - MySQL Database
- **3389** - RDP (Remote Desktop)
- **5900** - VNC (Remote desktop)
- **6667** - IRC (Command & Control)
- **31337** - Back Orifice (Trojan)
- **12345** - NetBus (Trojan)

## Customization

### Adjust Detection Thresholds

Edit `packet_sniffer.c`:

```c
/* Threat detection thresholds */
#define SUSPICIOUS_PACKET_SIZE 1400  // Bytes - adjust for your network
#define PORT_SCAN_THRESHOLD 10       // Number of ports before alert
#define TIME_WINDOW 60               // Time window in seconds
```

### Add More Suspicious Ports

Edit `packet_sniffer.c`:

```c
int suspicious_ports[] = {
    21,    // FTP
    23,    // Telnet
    // Add your ports here:
    8080,  // HTTP Proxy
    4444,  // Metasploit default
    0      // Keep this terminator!
};
```

After changes:
```bash
make clean
make
```

## Testing the Program

### Generate Test Traffic

**Terminal 1 - Run sniffer:**
```bash
sudo ./packet_sniffer
```

**Terminal 2 - Generate traffic:**
```bash
# Normal traffic
ping google.com
curl https://example.com

# SSH traffic (port 22)
ssh localhost

# HTTP traffic
wget https://www.google.com
```

### Test with Nmap (Port Scanning Detection)

**IMPORTANT**: Only scan your own machines!

```bash
# Install nmap
sudo apt install nmap

# Run sniffer in Terminal 1
sudo ./packet_sniffer

# Scan localhost in Terminal 2 (should trigger PORT_SCAN alert)
nmap -p 1-100 localhost

# Different scan types
nmap -sN localhost  # NULL scan
nmap -sX localhost  # XMAS scan
```

## Security & Legal Notes

⚠️ **IMPORTANT**:
- Only monitor networks you own or have permission to monitor
- Packet capture can see sensitive data (passwords, etc.)
- Always comply with local laws and regulations
- This tool is for educational and authorized security testing ONLY

## Next Steps

1. ✅ Install dependencies (`sudo apt-get install libpcap-dev`)
2. ✅ Compile the program (`make`)
3. ✅ Find your network interface (`ip link show`)
4. ✅ Run the sniffer (`sudo ./packet_sniffer eth0`)
5. ✅ Install VSCode for development (`sudo snap install code --classic`)
6. ✅ Customize thresholds and ports as needed

## Support

**Project Location**: `~/development/al4nbr3/`

**Files**:
- `packet_sniffer.c` - Main source code
- `Makefile` - Build configuration
- `README.md` - Full documentation
- `SETUP.md` - This file

**Makefile Commands**:
```bash
make          # Build
make clean    # Clean build files
make run      # Build and run
make install  # Install system-wide
make help     # Show all commands
```

---

**Ready to start! Just run the installation commands above.**
