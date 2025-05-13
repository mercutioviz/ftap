# Find The Admin Panel - Changelog

All notable changes to this project will be documented in this file.

## [6.0] - 2023-06-01

### Added
- Advanced Logging System with separate log files for errors, warnings, and usage
- Ctrl+C handling to stop scans and display results (single press) or exit (double press)
- Consolidated configuration system using only config.json as the source of truth
- New user agents list in config.json with improved browser coverage
- Automatic path validation and limiting based on configuration
- System information logging for better diagnostics
- Automatic log rotation and cleanup of logs older than 30 days
- Usage statistics tracking (scan count, success rate, etc.)
- Added more user-facing feature detection to filter out regular website pages
- Enhanced distinction between user login pages and admin login pages
- New admin-specific pattern recognition to reduce false positives

### Changed
- Enhanced signal handling for better user experience
- Improved result summary display with confidence scores
- Refactored code to remove redundancy and improve maintainability
- All settings now load from config.json exclusively
- Improved error handling and reporting
- Code optimization for better performance
- Adjusted scoring weights for login forms to prioritize admin-related forms
- Enhanced penalty system for user-oriented pages

### Fixed
- Export errors when result objects miss expected keys
- Path count issues when exceeding available paths
- Confidence score calculation to properly handle percentage values
- Various minor bugs and edge cases
- Fixed issue with regular login pages being incorrectly identified as admin 
panels
- Optimized content analysis to better distinguish between admin and user areas
- Addressed reliability issues in confidence scoring for multilingual websites

## [5.0] - 2023-01-15

### Added
- Multi-language support with automatic language detection
- Enhanced Arabic support with proper RTL handling
- Advanced results analysis for better accuracy
- Support for stealth mode to avoid detection

### Changed
- Improved scan engine with better performance
- Enhanced user interface with rich formatting
- Updated user agents for better compatibility

## [4.0] - 2022-09-20

### Added
- Headless browser support for JavaScript-heavy sites
- CAPTCHA detection and avoidance
- Export results in multiple formats (JSON, CSV, HTML)
- Advanced target information gathering

### Fixed
- SSL verification issues
- Connection timeouts handling
- Path traversal detection

## [3.0] - 2022-05-10

### Added
- Multi-site scanning capabilities
- Proxy support for anonymous scanning
- Advanced detection modes
- Custom user agent configuration

### Changed
- Improved console output with colored formatting
- Enhanced scan algorithms for better accuracy

## [2.0] - 2022-01-25

### Added
- Concurrent scanning for faster results
- Result caching to avoid duplicate requests
- Basic HTML report generation
- Command line interface improvements

### Fixed
- Path handling for different server types
- Result filtering for better accuracy

## [1.0] - 2021-11-05

### Added
- Initial release with basic scanning functionality
- Common admin panel paths detection
- Simple console output
- Basic configuration options
