# Find The Admin Panel
A powerful and advanced web scanning tool designed to discover admin panels, login pages, and administrative interfaces on websites. Features multiple scanning modes, proxy support, and comprehensive reporting.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-orange)
![Version](https://img.shields.io/badge/version-5.0-green)
![Last Updated](https://img.shields.io/badge/last%20updated-March%202025-yellow)

<div align="center">
  <img src="https://img.shields.io/badge/Security-Tool-red.svg" alt="Security Tool">
  <img src="https://img.shields.io/badge/Web-Scanner-blue.svg" alt="Web Scanner">
  <img src="https://img.shields.io/badge/Admin-Finder-green.svg" alt="Admin Finder">
</div>

<p align="center">
  <b>Advanced Web Scanner for Discovering Admin Panels, Login Pages, and Control Interfaces</b>
</p>

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Installation](#-installation)
  - [Windows](#windows)
  - [Linux](#linux)
  - [macOS](#macos)
  - [Termux](#termux)
- [Usage](#-usage)
  - [Basic Usage](#basic-usage)
  - [Interactive Menu](#interactive-menu)
  - [Command Line Options](#command-line-options)
- [Configuration](#-configuration)
  - [Detection Modes](#detection-modes)
  - [Settings Management](#settings-management)
- [Advanced Usage](#-advanced-usage)
  - [Performance Optimization](#performance-optimization)
  - [Custom Configurations](#custom-configurations)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

## 🚀 Overview

Find The Admin Panel is an advanced web scanning tool designed to discover administrative interfaces, login pages, and control panels on web applications. It features an interactive menu system, multiple scanning modes, and comprehensive configuration options to suit different scanning needs.

## 🔧 Features

### Core Features
- Interactive menu system with easy navigation
- Multiple scanning modes (Simple, Aggressive, Stealth)
- Real-time progress tracking with ETA
- Comprehensive settings management
- Results viewer with filtering capabilities

### Scanning Capabilities
- Admin panel detection
- Login form identification
- Technology fingerprinting
- Security header analysis
- CAPTCHA detection
- Form analysis
- Path enumeration

### Advanced Features
- Proxy/VPN support
- Headless browser integration
- Custom User-Agent rotation
- Rate limiting
- Connection pooling
- SSL/TLS support

### Reporting
- Interactive HTML reports
- JSON/CSV exports
- Real-time statistics
- Confidence scoring

## 🛠️ Installation

### Windows

1. **Install Python**
   ```bash
   # Download Python 3.7+ from python.org
   # During installation, check "Add Python to PATH"
   ```

2. **Install Git**
   ```bash
   # Download Git from git-scm.com
   ```

3. **Clone and Setup**
   ```bash
   # Open Command Prompt or PowerShell
   git clone https://github.com/dv64/Find-The-Admin-Panel.git
   cd Find-The-Admin-Panel
   pip install -r requirements.txt
   pip install playwright
   playwright install chromium
   ```

### Linux

1. **Install Dependencies**
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install python3 python3-pip git

   # Fedora
   sudo dnf install python3 python3-pip git

   # Arch Linux
   sudo pacman -S python python-pip git
   ```

2. **Clone and Setup**
   ```bash
   git clone https://github.com/dv64/Find-The-Admin-Panel.git
   cd Find-The-Admin-Panel
   pip3 install -r requirements.txt
   pip3 install playwright
   playwright install chromium
   ```

### macOS

1. **Install Homebrew**
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Install Python and Git**
   ```bash
   brew install python git
   ```

3. **Clone and Setup**
   ```bash
   git clone https://github.com/dv64/Find-The-Admin-Panel.git
   cd Find-The-Admin-Panel
   pip3 install -r requirements.txt
   pip3 install playwright
   playwright install chromium
   ```

### Termux

1. **Install Dependencies**
   ```bash
   pkg update
   pkg install python git
   ```

2. **Clone and Setup**
   ```bash
   git clone https://github.com/dv64/Find-The-Admin-Panel.git
   cd Find-The-Admin-Panel
   pip install -r requirements.txt
   ```

## 📋 Usage

### Basic Usage

1. **Start Interactive Menu**
   ```bash
   python Finder.py
   ```

2. **Direct Scan**
   ```bash
   python Finder.py -u https://example.com
   ```

3. **With Custom Paths**
   ```bash
   python Finder.py -u https://example.com -p custom_paths.json
   ```

4. **With Proxy**
   ```bash
   python Finder.py -u https://example.com --proxy http://127.0.0.1:8080
   ```

5. **Export Results**
   ```bash
   python Finder.py -u https://example.com --json --html --csv
   ```

### Interactive Menu

#### Main Menu Options
1. **Start Scan**
   - Enter target URL
   - Choose scanning mode
   - Configure scan settings
   - Monitor progress in real-time

2. **Settings**
   - Detection Mode Configuration
   - Proxy Settings
   - Browser Settings
   - Path Settings
   - Output Settings

3. **View Results**
   - Browse previous scans
   - Filter and sort results
   - Export in various formats
   - Detailed result analysis

4. **Help**
   - Usage guide
   - Command reference
   - Best practices
   - Troubleshooting tips

### Command Line Options

```bash
# Basic Options
-u, --url         Target URL to scan
-p, --pathfile    Custom path file (JSON format)
-o, --output      Output file for results

# Export Options
-j, --json        Save results in JSON format
-c, --csv         Save results in CSV format
-h, --html        Save results in HTML format

# Scan Options
--mode            Scan mode (simple/aggressive/stealth)
--concurrency     Number of concurrent requests
--batch-size      Number of URLs per batch
--timeout         Request timeout in seconds

# Privacy Options
--proxy           Use proxy server
--proxy-file      File containing list of proxies
--user-agent      Custom User-Agent string

# Other Options
-q, --quiet       Quiet mode (less output)
--no-verify       Disable SSL verification
--no-headless     Disable headless browser
```

## ⚙️ Configuration

### Detection Modes

#### Simple Mode
- Basic detection
- Minimal footprint
- Fast scanning
- Default concurrency: 25
- Recommended for: Quick scans, initial reconnaissance

#### Aggressive Mode
- Deep scanning
- Maximum detection
- Higher concurrency
- Additional checks
- Recommended for: Thorough analysis, penetration testing

#### Stealth Mode
- Evasive techniques
- Slower scanning
- Random delays
- Proxy rotation
- Recommended for: Avoiding detection, sensitive targets

### Settings Management

#### Proxy Configuration
- Single proxy setup
- Proxy list management
- Rotation settings
- Health monitoring

#### Browser Settings
- Headless mode
- User agent rotation
- Cookie management
- JavaScript handling

#### Path Settings
- Custom path lists
- Path prioritization
- Exclusion rules
- Pattern matching

#### Output Settings
- Report formats
- Export locations
- Log levels
- Result filtering

## 🔍 Advanced Usage

### Performance Optimization

```bash
# High performance scan
python Finder.py -u https://example.com --mode aggressive --concurrency 50

# Memory-efficient scan
python Finder.py -u https://example.com --batch-size 10 --cache-size 500

# Stealth scan with proxy rotation
python Finder.py -u https://example.com --mode stealth --proxy-file proxies.txt
```

### Custom Configurations

```bash
# Save custom settings
python Finder.py --save-config custom_config.json

# Load custom settings
python Finder.py --load-config custom_config.json

# Reset to defaults
python Finder.py --reset-config
```

## ❓ Troubleshooting

### Common Issues

1. **Connection Errors**
   ```bash
   # Increase timeout
   python Finder.py -u https://example.com --timeout 30
   ```

2. **Memory Usage**
   ```bash
   # Reduce batch size
   python Finder.py -u https://example.com --batch-size 10
   ```

3. **Rate Limiting**
   ```bash
   # Enable proxy rotation
   python Finder.py -u https://example.com --proxy-file proxies.txt
   ```

4. **SSL Errors**
   ```bash
   # Disable SSL verification
   python Finder.py -u https://example.com --no-verify
   ```

5. **Browser Issues**
   ```bash
   # Disable headless mode
   python Finder.py -u https://example.com --no-headless
   ```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Made by DV64
</p>
