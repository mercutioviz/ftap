# Find The Admin Panel
A powerful and advanced web scanning tool designed to discover admin panels, login pages, and administrative interfaces on websites. Features multiple scanning modes, proxy support, and comprehensive reporting.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.7%2B-orange)
![Version](https://img.shields.io/badge/version-6.0-green)
![Last Updated](https://img.shields.io/badge/last%20updated-May%202025-yellow)

<div align="center">
  <img src="https://img.shields.io/badge/Security-Tool-red.svg" alt="Security Tool">
  <img src="https://img.shields.io/badge/Web-Scanner-blue.svg" alt="Web Scanner">
  <img src="https://img.shields.io/badge/Admin-Finder-green.svg" alt="Admin Finder">
</div>

- **Advanced Scanning**: Multiple scan modes (aggressive, stealth, simple)
- **Smart Detection**: Analyzes responses to identify potential admin panels
- **Enhanced Logging**: Comprehensive logging system with separate logs for errors, warnings, and usage
- **Configuration System**: All settings are centralized in `config.json`
- **Ctrl+C Handling**: Press once to stop scan and show results, press twice to exit
- **Export Options**: Export results to multiple formats (JSON, HTML, CSV, TXT)
- **Performance**: Asynchronous processing and concurrent requests for faster scanning
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
python finder.py -u https://example.com --mode aggressive --concurrency 50 -j -h -c
```

### Parameters

- `-u, --url`: Target URL to scan
- `--mode`: Scan mode (aggressive, stealth, simple, all)
- `-p, --paths`: Path to the paths file (default: general_paths.json)
- `-c, --concurrency`: Number of concurrent requests (default: from config.json)
- `-t, --timeout`: Request timeout in seconds (default: from config.json)
- `-j, --json`: Export results to JSON
- `-h, --html`: Export results to HTML
- `--csv`: Export results to CSV
- `--txt`: Export results to TXT
- `--no-verify`: Disable SSL verification
- `--output`: Output file prefix

## Configuration

All settings are stored in `config/config.json`. This centralized approach allows for easy customization without modifying the source code.

### Key Configuration Settings:

- `VERSION`: Current version of the application
- `DEVELOPER`: Developer name (DV64)
- `RELEASE_DATE`: Release date of the current version
- `USER_AGENTS`: List of user agent strings for request headers
- `MAX_CONCURRENT_TASKS`: Maximum number of concurrent requests (default: 50)
- `CONNECTION_TIMEOUT`: Timeout for HTTP requests in seconds (default: 10)
- `READ_TIMEOUT`: Timeout for reading response in seconds (default: 20)
- `DETECTION_MODE`: Default scan mode (aggressive, stealth, simple)
- `MAX_PATHS`: Maximum number of paths to scan in a single run
- `CUSTOM_PATHS_FILE`: Path to the custom paths file (defaults to general_paths.json)
- `VERIFY_SSL`: Whether to verify SSL certificates (default: false)
- `EXPORT_FORMATS`: Default export formats (json, html, csv, txt)
- `AUTO_ADJUST_CONCURRENCY`: Automatically adjust concurrency based on server response
- `SAVE_RESULTS`: Whether to save results automatically
- `RESULTS_DIR`: Directory to save results

Customize these settings to optimize the tool for your specific scanning needs and target environment.

## Response Handling

- **Ctrl+C (once)**: Stop current scan and display found results
- **Ctrl+C (twice)**: Exit the application completely

## Directory Structure

```
├── config/
│   └── config.json         # Configuration file
├── logs/                   # Log files directory
├── paths/
│   └── general_paths.json  # Default paths file
├── results/                # Scan results directory
├── scripts/
│   ├── scan_helper.py      # Helper functions for scanning
│   └── logging.py          # Advanced logging system
├── finder.py               # Main application file
├── requirements.txt        # Dependencies
└── README.md               # This file
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational purposes only. Use responsibly and only on systems you own or have permission to test.

## Credits

Developed and maintained by DV64 © 2025.  
All rights reserved.
