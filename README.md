# Find The Admin Panel

## Description

**Find The Admin Panel** is a powerful Python tool designed for web security researchers, penetration testers, and system administrators to efficiently discover admin panels, login pages, and other sensitive areas of web applications. The tool leverages asynchronous processing to check multiple paths concurrently, providing faster and more reliable results.

## Key Features

- **Fast Scanning**: Asynchronous implementation for high-speed scanning
- **Multiple Path Sources**: Uses both built-in paths and custom paths from JSON files
- **Smart Detection**: Identifies admin panels with confidence-based scoring system
- **Comprehensive Technology Detection**: Recognizes web technologies, frameworks, and security headers
- **Flexible Output Options**: Generates both text and JSON reports
- **Modern User Interface**: Rich terminal display with colors and progress indicators
- **Customizable Options**: Set concurrency level, custom path lists, and more

---

## Installation

### Prerequisites

- Python 3.7+
- Required packages (specified in requirements.txt)

### Installing on Linux/macOS

```bash
# Clone the repository
git clone https://github.com/DV64/Find-The-Admin-Panel.git
cd Find-The-Admin-Panel

# Install dependencies
pip3 install -r requirements.txt

# Run the scanner
python3 Find.py
```

### Installing on Windows

```bash
# Clone the repository
git clone https://github.com/DV64/Find-The-Admin-Panel.git
cd Find-The-Admin-Panel

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python Find.py
```

## Usage

### Basic Usage

```bash
python Find.py
```

This will start the scanner in interactive mode, prompting you for the target URL.

### Command Line Options

```bash
python Find.py -u https://example.com
```

### Available Command Line Arguments

- `-u, --url`: Target URL to scan
- `-p, --pathfile`: Custom path file (JSON format)
- `-o, --output`: Output file for results
- `-j, --json`: Save results in JSON format
- `-q, --quiet`: Quiet mode (less output)
- `-c, --concurrency`: Number of concurrent requests (default: 25)
- `-h, --help`: Show help information

### Examples

```bash
# Basic scan with default settings
python Find.py -u https://example.com

# Use a custom path file and save results as JSON
python Find.py -u https://example.com -p custom_paths.json -j

# Run a quiet scan with 50 concurrent requests
python Find.py -u https://example.com -q -c 50

# Specify output file name
python Find.py -u https://example.com -o my_scan_results
```

### Path Files

The scanner supports two sources of paths to scan:
1. **Built-in paths**: Default list of common admin paths
2. **Custom paths**: Loaded from a JSON file

To use custom paths, create a JSON file (e.g., `sub_links.json`) with an array of paths:

```json
[
  "admin",
  "administrator",
  "login",
  "wp-admin",
  ...
]
```

---

## Understanding Results

The scanner provides detailed information about each discovered page:

- **URL**: Complete URL of the discovered page
- **Status Code**: HTTP status code
- **Response Time**: Time taken to receive the response
- **Server**: Server technology (Apache, Nginx, etc.)
- **Technologies**: Detected web technologies (WordPress, Laravel, etc.)
- **Forms Found**: Number of HTML forms on the page
- **Login Form**: Whether a login form was detected
- **Confidence**: Probability that the page is an admin panel

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Disclaimer

This tool is for educational and ethical security research purposes only. Always ensure you have explicit permission to scan any website or system. Unauthorized scanning may be illegal and unethical.
