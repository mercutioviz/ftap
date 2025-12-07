# Find The Admin Panel
A powerful and advanced web scanning tool designed to discover admin panels, login pages, and administrative interfaces on websites. Features multiple scanning modes, proxy support, and comprehensive reporting.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-orange)
![Version](https://img.shields.io/badge/version-6.1-green)
![Last Updated](https://img.shields.io/badge/last%20updated-Jul%202025-yellow)

<div align="center">
  <img src="https://img.shields.io/badge/Security-Tool-red.svg" alt="Security Tool">
  <img src="https://img.shields.io/badge/Web-Scanner-blue.svg" alt="Web Scanner">
  <img src="https://img.shields.io/badge/Admin-Finder-green.svg" alt="Admin Finder">
</div>

- **Advanced Scanning**: Multiple scan modes (aggressive, stealth, simple) with distinct behaviors
- **Smart Detection**: Analyzes responses with improved error page detection to reduce false positives
- **Enhanced Logging**: Comprehensive logging system with auto-creation of required directories
- **Configuration System**: Tailored settings for each scan mode in `config.json`
- **Real-time Tracking**: Live progress updates showing found, verified, and rejected results
- **Ctrl+C Handling**: Press once to stop scan and show results, press twice to exit
- **Export Options**: Export results to multiple formats (JSON, HTML, CSV, TXT)
- **Performance**: Asynchronous processing and concurrent requests with mode-specific optimization
- **User-Friendly**: Rich terminal interface with progress tracking and statistics

## Installation

```bash
# Clone the repository
git clone https://github.com/DV64/Find-The-Admin-Panel.git
cd Find-The-Admin-Panel

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python finder.py -u https://example.com
```

### Advanced Options

```bash
python finder.py --url https://example.com --detection-mode aggressive --concurrency 30 --export html
```

### Parameters

- `-u, --url`: Target URL to scan
- `-w, --wordlist`: Path to wordlist file (default: paths/general_paths.json)
- `-e, --export`: Export format (json, html, csv, txt)
- `-f, --filename`: Output file name (Custom CLI option added by mercutioviz)
- `-d, --directory`: Output directory (Custom CLI option added by mercutioviz)
- `-i, --interactive`: Run in interactive mode with UI
- `-v, --version`: Show version and exit
- `--detection-mode`: Set the detection mode (simple, stealth, aggressive)
- `--concurrency`: Set maximum concurrent requests
- `--http3`: Enable HTTP/3 protocol support
- `--update-wordlist`: Update wordlists with latest paths
- `--machine-learning`: Enable machine learning-based detection
- `--fuzzing`: Enable path fuzzing capabilities

## Scan Modes

The tool offers three distinct scanning modes, each optimized for different scenarios:

### Simple Mode
- Fast scanning with minimal evasion techniques
- Uses fewer paths (up to 1000) for quicker results
- Best for initial reconnaissance or when time is limited
- Command: `--detection-mode simple`

### Stealth Mode
- Slower scanning with advanced evasion techniques
- Uses delays between requests and randomization
- Carefully selects paths containing admin-related keywords
- Designed to avoid detection by WAFs and security systems
- Command: `--detection-mode stealth`

### Aggressive Mode
- Maximum speed scanning with comprehensive path checking
- Uses all available paths with high concurrency
- Verifies found results to minimize false positives
- Best when thorough scanning is required
- Command: `--detection-mode aggressive`

## Configuration

All settings are stored in `config/config.json`. This centralized approach allows for easy customization without modifying the source code.

### Key Configuration Settings:

- `VERSION`: Current version of the application
- `DEVELOPER`: Developer name (DV64)
- `DETECTION_MODES`: Available scan modes (simple, stealth, aggressive)
- `MODE_CONFIGS`: Mode-specific settings for each scan type
- `MAX_CONCURRENT_TASKS`: Maximum number of concurrent requests
- `CONNECTION_TIMEOUT`: Timeout for HTTP requests in seconds
- `READ_TIMEOUT`: Timeout for reading response in seconds
- `DETECTION_MODE`: Default scan mode (aggressive, stealth, simple)
- `MAX_PATHS`: Maximum number of paths to scan in a single run
- `CUSTOM_PATHS_FILE`: Path to the custom paths file
- `VERIFY_SSL`: Whether to verify SSL certificates (default: false)
- `EXPORT_FORMATS`: Default export formats (json, html, csv, txt)
- `AUTO_ADJUST_CONCURRENCY`: Automatically adjust concurrency based on server response
- `SAVE_RESULTS`: Whether to save results automatically
- `RESULTS_DIR`: Directory to save results
- `LOGS_DIR`: Directory for log files

## Response Handling

- **Ctrl+C (once)**: Stop current scan and display found results
- **Ctrl+C (twice)**: Exit the application completely

## Directory Structure

```
├── config/
│   └── config.json         # Configuration file
├── logs/                   # Log files directory
│   ├── error.log           # Error logs
│   ├── warning.log         # Warning logs
│   ├── info.log            # Information logs
│   ├── master.log          # Complete logs
│   ├── usage.log           # Usage statistics
│   └── success.txt         # Found admin panels
├── paths/
│   └── general_paths.json  # Default paths file
├── results/                # Scan results directory
├── scripts/
│   ├── config.py           # Configuration handling
│   ├── exporter.py         # Results export functionality
│   ├── logging.py          # Advanced logging system
│   ├── menu.py             # Interactive menu system
│   ├── scan_helper.py      # Helper functions for scanning
│   ├── scanner.py          # Core scanning functionality
│   └── ui.py               # Terminal UI components
├── finder.py               # Main application file
├── requirements.txt        # Dependencies
└── README.md               # This file
```

## What's New in v6.1

- Fixed issue where logs and results were not being saved correctly
- Fixed false positives in admin panel detection with improved 404 page detection
- Implemented unique behavior for each scan mode (simple, stealth, aggressive)
- Added real-time progress tracking showing found, verified, and rejected results
- Added verification step for discovered admin panels to reduce false positives
- Improved path selection based on scan mode with optimization for each type
- Enhanced error page detection even when status code is 200
- Ensured compatibility with sites using Cloudflare protection
- For complete changelog, see CHANGELOG.md

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational purposes only. Use responsibly and only on systems you own or have permission to test.

## Credits

Developed and maintained by DV64 © 2025.  
All rights reserved.

