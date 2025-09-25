# 🛡️ WiFi Network Security Auditor

**Professional Network Security Auditing Tool for Educational and Administrative Purposes**

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Educational-orange.svg)

## ⚠️ LEGAL DISCLAIMER

**🚨 IMPORTANT: THIS TOOL IS FOR EDUCATIONAL AND LEGITIMATE NETWORK ADMINISTRATION PURPOSES ONLY**

- ✅ **LEGAL USE**: Your own home/business network where you have administrative rights
- ✅ **EDUCATIONAL**: Learning network security concepts and protocols
- ✅ **AUTHORIZED TESTING**: Networks where you have explicit written permission
- ❌ **ILLEGAL USE**: Unauthorized access to third-party networks
- ❌ **MALICIOUS USE**: Any form of unauthorized network interference

**The user is solely responsible for compliance with local laws and regulations.**

## 🎯 Features

### 🔍 **Network Discovery & Analysis**
- **Smart Device Detection**: Automatically identifies device types (📱 phones, 💻 computers, 📺 TVs, 🎮 consoles)
- **Vendor Identification**: Recognizes manufacturers (Apple, Samsung, Google, etc.)
- **Real-time Monitoring**: Continuous network surveillance with alerts
- **MAC Address Analysis**: Advanced device fingerprinting

### 📊 **Professional Reporting**
- **Visual Interface**: Color-coded, emoji-enhanced device listings
- **Device Categories**: Smart categorization (IoT, mobile, entertainment, etc.)
- **Network Mapping**: Complete topology visualization
- **Security Logging**: Comprehensive audit trails

### 🛡️ **Security Features**
- **Whitelist Protection**: Safeguard authorized devices
- **Admin Self-Protection**: Prevents accidental self-disconnection  
- **Confirmation Prompts**: Safety checks before critical actions
- **Rate Limiting**: Prevents abuse with built-in throttling

### ⚙️ **Advanced Configuration**
- **Auto-Detection**: Automatically discovers network settings
- **Multi-Platform**: Linux and macOS compatibility
- **Fallback Methods**: Multiple scanning techniques (Scapy, nmap, ping)
- **JSON Configuration**: Easy customization and deployment

## 🚀 Quick Start

### Prerequisites
- Python 3.7 or higher
- Administrator/root privileges
- Compatible WiFi interface
- Target network must be your own

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/wifi-security-auditor.git
cd wifi-security-auditor

# Install dependencies
pip3 install -r requirements.txt

# Run the installer (optional)
sudo bash install_wifi_bot.sh
```

### Basic Usage

```bash
# Network discovery scan
sudo python3 wifi.py --scan

# Interactive mode
sudo python3 wifi.py

# Command line device management
sudo python3 wifi.py --target AA:BB:CC:DD:EE:FF --disconnect

# Custom configuration
sudo python3 wifi.py --config custom_config.json
```

## 📋 System Requirements

### Operating Systems
- **Linux**: Ubuntu 18.04+, Debian 10+, CentOS 8+, Arch Linux
- **macOS**: 10.14+ (with limitations)

### Hardware Requirements
- WiFi interface capable of monitor mode (for full functionality)
- Minimum 2GB RAM
- 100MB free disk space

### Software Dependencies
- Python 3.7+
- Scapy (network packet manipulation)
- Standard system tools (ifconfig/ip, arp, ping)

## 🎮 Interactive Mode

```
==================================================
            WIFI NETWORK ADMINISTRATOR            
==================================================
1. 🔍 Scan Network        - Discover connected devices
2. 📱 Show Devices        - List all detected devices  
3. 🚫 Disconnect Device   - Manage device access
4. 👀 Monitor Mode        - Continuous surveillance
5. ⚙️  Configure Interface - Setup network adapter
6. 🛠️  Settings           - Customize behavior
7. 📋 View Logs           - Check activity history
0. 🚪 Exit               - Close application
```

### Sample Device Detection Output

```
================================================================================
                            CONNECTED DEVICES                                   
================================================================================
#   IP              MAC                Type                 Vendor       Status
--------------------------------------------------------------------------------
1   192.168.1.1     aa:bb:cc:dd:ee:ff  🌐 Router/Gateway   TP-Link      online
2   192.168.1.10    11:22:33:44:55:66  📱 iPhone           Apple        online  
3   192.168.1.15    77:88:99:aa:bb:cc  💻 MacBook          Apple        online
4   192.168.1.20    12:34:56:78:90:ab  📺 Smart TV         Samsung      online
5   192.168.1.25    ab:cd:ef:12:34:56  🎮 PlayStation      Sony         online
```

## ⚙️ Configuration

### Auto-Detection
The tool automatically detects:
- Active network interface
- Gateway/router IP address  
- Network range (CIDR notation)
- Device types and manufacturers

### Manual Configuration (`wifi_config.json`)

```json
{
    "network": {
        "interface": "auto-detect",
        "gateway": "auto-detect", 
        "network_range": "auto-detect"
    },
    "security": {
        "whitelist": ["your:device:mac:here"],
        "require_confirmation": true,
        "max_actions_per_hour": 10
    },
    "ui": {
        "show_device_types": true,
        "show_vendor_info": true,
        "use_colors": true,
        "show_icons": true
    }
}
```

## 🔧 Advanced Features

### Device Type Recognition
Automatically identifies:
- 📱 **Mobile Devices**: iPhone, Android, tablets
- 💻 **Computers**: Laptops, desktops, servers  
- 📺 **Entertainment**: Smart TVs, streaming devices, consoles
- 🌐 **Network**: Routers, access points, extenders
- 🔊 **IoT**: Smart speakers, home automation
- 🖨️ **Peripherals**: Printers, scanners, storage

### Security Mechanisms
- **Multi-Method Disconnection**: Scapy deauth, aireplay-ng, mdk3
- **Graceful Fallbacks**: Works even with limited permissions
- **Educational Mode**: Safe simulation when tools unavailable
- **Comprehensive Logging**: All actions tracked and timestamped

## 🛠️ Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Solution: Run with administrator privileges
sudo python3 wifi.py
```

#### Module Not Found
```bash
# Solution: Install dependencies
pip3 install -r requirements.txt
```

#### No Devices Detected
- Verify you're connected to the target network
- Check network configuration (gateway, range)
- Ensure target devices are active
- Try different scanning methods

### Platform-Specific Notes

#### macOS Limitations
- Monitor mode limited by system restrictions
- Some advanced features require additional tools
- SIP (System Integrity Protection) may interfere

#### Linux Recommendations
- Install aircrack-ng suite for full functionality
- Use dedicated USB WiFi adapters for best results
- Ensure wireless drivers support monitor mode

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)  
5. Open a Pull Request

### Development Setup

```bash
# Clone for development
git clone https://github.com/yourusername/wifi-security-auditor.git
cd wifi-security-auditor

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

## 📚 Educational Resources

### Learning Network Security
- [WiFi Security Fundamentals](https://example.com/wifi-security)
- [802.11 Protocol Deep Dive](https://example.com/80211-protocol)  
- [Network Administration Best Practices](https://example.com/network-admin)
- [Ethical Hacking Guidelines](https://example.com/ethical-hacking)

### Related Tools
- **Wireshark**: Network protocol analyzer
- **Aircrack-ng**: WiFi security auditing suite
- **Nmap**: Network discovery and security auditing
- **Kismet**: Wireless network detector

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 WiFi Security Auditor Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

## 🆘 Support

### Getting Help
- 📖 Check the [documentation](docs/)
- 🐛 Report bugs via [GitHub Issues](../../issues)
- 💬 Join our [community discussions](../../discussions)
- 📧 Contact: security.auditor@example.com

### Professional Support
For enterprise deployments and professional consulting:
- Network security assessments
- Custom tool development  
- Training and workshops
- Compliance auditing

---

## ⭐ Show Your Support

Give a ⭐️ if this project helped you learn about network security!

### Project Stats
![GitHub stars](https://img.shields.io/github/stars/yourusername/wifi-security-auditor)
![GitHub forks](https://img.shields.io/github/forks/yourusername/wifi-security-auditor)
![GitHub issues](https://img.shields.io/github/issues/yourusername/wifi-security-auditor)

---

**🛡️ Built with security, education, and responsibility in mind. 🛡️**

*Remember: With great power comes great responsibility. Use this tool ethically and legally.*
