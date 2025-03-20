import os
import json
import asyncio
import aiohttp
import argparse
import platform
import logging 
import time
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple, Any, Union
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from rich import print as rprint
from rich.console import Console
from rich.progress import Progress, TaskID, TextColumn, BarColumn, TimeRemainingColumn, SpinnerColumn
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.tree import Tree
from rich.box import Box, ROUNDED
from rich.columns import Columns
from rich.markdown import Markdown
from rich.console import Group
import ssl
import certifi
from colorama import init, Fore, Style
import cachetools
import signal
import random
import sys
import csv
import html
import requests
import socket
import re
import subprocess
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

init(autoreset=True)

# Initialize global rich console
console = Console()

@dataclass
class Config:
    VERSION: str = "5.0"
    DEVELOPER: str = "DV64"
    GITHUB: str = "https://github.com/dv64"
    TOOL_NAME: str = "Find The Admin Panel"
    RELEASE_DATE: str = "2025"
    CACHE_TTL: int = 3600
    CACHE_SIZE: int = 1000
    MAX_CONCURRENT_TASKS: int = 50
    CONNECTION_TIMEOUT: int = 10
    READ_TIMEOUT: int = 45  # Increased from 20 to 45
    BATCH_SIZE: int = 25
    VERIFY_SSL: bool = False
    MAX_RETRIES: int = 3
    RETRY_DELAY: float = 1.5
    RETRY_JITTER: float = 0.5  # Randomness in retry times to avoid rate limiting
    MAX_CONCURRENT_RETRIES: int = 3  # Number of retry attempts
    TIMEOUT_BACKOFF_FACTOR: float = 2.0  # Exponential backoff factor
    AUTO_ADJUST_CONCURRENCY: bool = True  # Dynamically adjust concurrency based on timeouts
    MAX_TIMEOUT_THRESHOLD: int = 5  # Threshold of timeouts before reducing concurrency
    USE_PROXIES: bool = False
    USE_HEADLESS_BROWSER: bool = False
    CAPTCHA_DETECTION: bool = True
    EXPORT_FORMATS: List[str] = field(default_factory=lambda: ["txt", "json", "csv", "html"])
    DETECTION_MODES: List[str] = field(default_factory=lambda: ["simple", "aggressive", "stealth"])
    DETECTION_MODE: str = "simple"  # Default detection mode
    SCAN_FREQUENCY: str = "once"  # once, hourly, daily, weekly
    MULTI_SITE_SCAN: bool = False
    LOGS_DIR: str = "logs"  # Directory for log files
    CUSTOM_PATHS_FILE: str = "sub_links.json"  # Default custom paths file
    MAX_PATHS: int = 5000  # Maximum number of paths to scan
    SAVE_RESULTS: bool = True  # Whether to save results by default
    RESULTS_DIR: str = "results"  # Directory for results
    USER_AGENTS: List[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:91.0) Gecko/20100101 Firefox/91.0"
    ])
    PROXIES: List[str] = field(default_factory=list)
    
    def save_config(self, filepath: str = "config.json"):
        """Save current configuration to a JSON file"""
        config_dict = {
            key: value for key, value in self.__dict__.items() 
            if not key.startswith('_') and not callable(value)
        }
        with open(filepath, 'w') as f:
            json.dump(config_dict, f, indent=4)
            
    def load_config(self, filepath: str = "config.json"):
        """Load configuration from a JSON file"""
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                config_dict = json.load(f)
                for key, value in config_dict.items():
                    if hasattr(self, key):
                        setattr(self, key, value)

class ProxyManager:
    """Handles proxy connections and rotation for anonymous scanning"""
    
    def __init__(self, config: 'Config'):
        self.config = config
        self.proxies = []
        self.current_proxy_index = 0
        self.last_rotate_time = time.time()
        self.session = None
        self.proxy_health = {}  # Track proxy health/success rate

    def load_proxies_from_file(self, filepath: str) -> bool:
        """Load proxies from a file (one proxy per line)"""
        try:
            with open(filepath, 'r') as f:
                self.proxies = [line.strip() for line in f if line.strip()]
            return True
        except Exception as e:
            logging.error(f"Failed to load proxies from {filepath}: {str(e)}")
            return False

    def add_proxy(self, proxy: str) -> None:
        """Add a single proxy to the list"""
        if proxy and proxy not in self.proxies:
            self.proxies.append(proxy)
            self.proxy_health[proxy] = {'success': 0, 'fail': 0}

    def get_next_proxy(self) -> Optional[str]:
        """Get the next proxy in rotation"""
        if not self.proxies:
            return None
            
        # Rotate based on success rate if we have data
        if self.proxy_health and all(stats['success'] + stats['fail'] > 0 for stats in self.proxy_health.values()):
            # Sort by success rate
            sorted_proxies = sorted(
                self.proxies,
                key=lambda p: self.proxy_health[p]['success'] / (self.proxy_health[p]['success'] + self.proxy_health[p]['fail'] + 0.1),
                reverse=True
            )
            return sorted_proxies[0]
        
        # Simple rotation if no health data yet
        proxy = self.proxies[self.current_proxy_index]
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
        return proxy
        
    def update_proxy_health(self, proxy: str, success: bool) -> None:
        """Update the health statistics for a proxy"""
        if proxy not in self.proxy_health:
            self.proxy_health[proxy] = {'success': 0, 'fail': 0}
            
        if success:
            self.proxy_health[proxy]['success'] += 1
        else:
            self.proxy_health[proxy]['fail'] += 1
            
    def format_proxy_for_aiohttp(self, proxy: str) -> str:
        """Format proxy string for aiohttp"""
        if proxy.startswith('http://') or proxy.startswith('https://'):
            return proxy
        return f'http://{proxy}'
        
    def get_proxy_status(self) -> Dict[str, Any]:
        """Get status information about the active proxies"""
        total_proxies = len(self.proxies)
        healthy_proxies = sum(1 for p in self.proxy_health.values() 
                             if p['success'] > p['fail'])
        
        return {
            'total': total_proxies,
            'healthy': healthy_proxies,
            'current': self.get_next_proxy() if self.proxies else None,
            'health': self.proxy_health
        }
    
    def check_proxy_connection(self, proxy: str) -> bool:
        """Test if a proxy is working"""
        try:
            test_url = "https://www.google.com"
            proxy_dict = {
                "http": self.format_proxy_for_aiohttp(proxy),
                "https": self.format_proxy_for_aiohttp(proxy)
            }
            
            response = requests.get(
                test_url,
                proxies=proxy_dict,
                timeout=5,
                verify=False
            )
            
            return response.status_code == 200
        except Exception as e:
            logging.debug(f"Proxy test failed for {proxy}: {str(e)}")
            return False

class TerminalDisplay:
    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        
    def clear_screen(self):
        """Clear the terminal screen"""
        # Use os-specific clear command
        if platform.system().lower() == "windows":
            os.system("cls")
        else:
            os.system("clear")
            
    def show_banner(self, config: Config):
        # Simple banner with just "Finder"
        banner = """
  ███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
  ██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
  █████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
  ██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
  ██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
  ╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
        """
        
        # Create a panel with a colorful gradient border
        banner_panel = Panel(
            banner,
            border_style="blue",
            style="bold bright_blue",
            subtitle=f"v{config.VERSION} - {config.RELEASE_DATE}",
            subtitle_align="right"
        )
        
        # Basic info in a simple format
        info_text = Text()
        info_text.append(f"Tool: {config.TOOL_NAME} | ", style="cyan")
        info_text.append(f"Dev: {config.DEVELOPER} | ", style="cyan")
        info_text.append(f"GitHub: {config.GITHUB}", style="cyan")
        
        # Print banner and info
        self.console.print(banner_panel)
        self.console.print(info_text)
        self.console.print("\n" + "=" * 70 + "\n")

    def show_target_info(self, url: str, scan_mode: str = "standard", proxies_enabled: bool = False, headless_enabled: bool = False):
        parsed_url = urlparse(url)
        
        # Get hostname IP info
        try:
            ip_address = socket.gethostbyname(parsed_url.netloc.split(':')[0])
        except socket.gaierror:
            ip_address = "Could not resolve hostname"
        
        target_layout = Layout()
        
        # Basic info panel
        basic_info = Text()
        basic_info.append("URL          : ", style="cyan")
        basic_info.append(f"{url}\n", style="white")
        basic_info.append("Domain       : ", style="cyan")
        basic_info.append(f"{parsed_url.netloc}\n", style="white")
        basic_info.append("Protocol     : ", style="cyan")
        basic_info.append(f"{parsed_url.scheme}\n", style="white")
        basic_info.append("IP Address   : ", style="cyan")
        basic_info.append(f"{ip_address}\n", style="white")
        basic_info.append("Scan Mode    : ", style="cyan")
        basic_info.append(f"{scan_mode}\n", style="white")
        basic_info.append("Start Time   : ", style="cyan")
        basic_info.append(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", style="white")
        
        # Scan settings panel
        settings_info = Text()
        settings_info.append("Proxies Enabled    : ", style="cyan")
        settings_info.append(f"{'Yes' if proxies_enabled else 'No'}\n", style="green" if proxies_enabled else "red")
        settings_info.append("Headless Browser   : ", style="cyan")
        settings_info.append(f"{'Yes' if headless_enabled else 'No'}\n", style="green" if headless_enabled else "red")
        
        basic_panel = Panel(
            basic_info,
            title="[bold cyan]Target Information",
            border_style="cyan",
            padding=(1, 2)
        )
        
        settings_panel = Panel(
            settings_info,
            title="[bold magenta]Scan Settings",
            border_style="magenta",
            padding=(1, 2)
        )
        
        # Create target info layout
        target_layout.split_row(
            Layout(basic_panel, name="basic_info"),
            Layout(settings_panel, name="settings_info")
        )
        
        self.console.print(target_layout)
        self.console.print("\n")

    def show_result(self, result: Dict, compact: bool = True):
        """Display a single result in a compact, eye-friendly format"""
        # Determine color based on confidence
        confidence = result["confidence"]
        if confidence >= 0.7:
            confidence_color = "green"
            confidence_label = "High"
        elif confidence >= 0.4:
            confidence_color = "yellow"
            confidence_label = "Medium"
        else:
            confidence_color = "red"
            confidence_label = "Low"
            
        # Determine status code color
        status_code = result["status_code"]
        if 200 <= status_code < 300:
            status_color = "green"
        elif 300 <= status_code < 400:
            status_color = "yellow"
        elif 400 <= status_code < 500:
            status_color = "red"
        else:
            status_color = "red"
        
        if compact:
            # Compact format: one line per result
            line = Text()
            line.append(f"[{status_color}]{status_code}[/] ", style="bold")
            line.append(f"{result['url']} ", style="white")
            line.append(f"({confidence*100:.1f}%) ", style=confidence_color)
            
            # Add minimal info
            if "title" in result and result["title"]:
                title = result["title"].strip()
                if len(title) > 40:
                    title = title[:37] + "..."
                line.append(f"[dim]Title:[/] {title} ", style="cyan")
                
            if result.get('has_login_form'):
                line.append("[green]Login[/] ", style="bold")
            
            if result.get('has_captcha'):
                line.append("[yellow]CAPTCHA[/] ", style="bold")
                
            return line
        else:
            # Legacy detailed format - kept for compatibility
            # Header for the result with URL and confidence
            header_text = Text()
            header_text.append("➤ ", style=confidence_color)
            header_text.append(f"{result['url']}", style="white bold")
            header_text.append(" [", style="dim")
            header_text.append(f"{confidence*100:.1f}% {confidence_label}", style=confidence_color)
            header_text.append("]", style="dim")
            
            # Details section with structured information
            details = Table.grid(padding=(0, 1))
            details.add_column("Label", style="cyan", no_wrap=True)
            details.add_column("Value", style="white")
            
            # Add rows for different information types
            details.add_row("Status", f"[{status_color}]{status_code}[/]")
            details.add_row("Response", f"{result['response_time']:.3f} seconds")
            
            if "server" in result:
                details.add_row("Server", result.get('server', 'Unknown'))
                
            if "title" in result:
                details.add_row("Title", result.get('title', 'No Title'))
            
            # Technology section
            tech_table = Table.grid(padding=(0, 1))
            tech_table.add_column(style="cyan")
            tech_table.add_column(style="white")
            
            if isinstance(result.get('technologies'), dict):
                for category, techs in result['technologies'].items():
                    if techs:
                        tech_table.add_row(f"{category.title()}:", f"{', '.join(techs)}")
            elif result.get('technologies'):
                tech_table.add_row("Technologies:", f"{', '.join(result['technologies'])}")
            else:
                tech_table.add_row("Technologies:", "None detected")
                
            # Protection/Forms section
            protection_table = Table.grid(padding=(0, 1))
            protection_table.add_column(style="cyan")
            protection_table.add_column(style="white")
            
            protection_table.add_row("Forms:", f"{result.get('forms', 0)}")
            protection_table.add_row("Inputs:", f"{result.get('inputs', 0)}")
            protection_table.add_row("Login Form:", 
                                f"[green]Yes[/]" if result.get('has_login_form', False) else "[red]No[/]")
            
            if "has_captcha" in result:
                protection_table.add_row("CAPTCHA:", 
                                    f"[yellow]Yes[/]" if result.get('has_captcha', False) else "[green]No[/]")
            
            # Create confidence indicator
            bar_width = 20
            filled_chars = int(confidence * bar_width)
            empty_chars = bar_width - filled_chars
            confidence_bar = "█" * filled_chars + "░" * empty_chars
            
            confidence_panel = Panel(
                Group(
                    Text.from_markup(f"[bold {confidence_color}]Confidence Score: {confidence*100:.1f}% ({confidence_label})[/]"),
                    Text.from_markup(f"[{confidence_color}]{confidence_bar}[/]")
                ),
                border_style=confidence_color,
                padding=(1, 1)
            )
            
            # Create main result panel with all components
            result_panel = Panel(
                Group(
                    header_text,
                    Text(""),
                    Panel(details, title="[cyan]Basic Information", border_style="cyan", padding=(1, 1)),
                    Panel(tech_table, title="[green]Technology Detection", border_style="green", padding=(1, 1)),
                    Panel(protection_table, title="[magenta]Form Analysis", border_style="magenta", padding=(1, 1)),
                    confidence_panel
                ),
                title=f"[bold cyan]Potential Admin Panel Found",
                border_style=confidence_color,
                padding=(1, 2)
            )
            
            # Print with a separator line
            self.console.print(result_panel)
            self.console.print("\n" + "─" * 80 + "\n")

    def show_summary(self, total_scanned: int, valid_found: int, scan_time: float, technologies: Dict[str, int] = None):
        # Calculate success rate
        success_rate = (valid_found / total_scanned) * 100 if total_scanned > 0 else 0
        if success_rate > 10:
            rate_color = "green"
        elif success_rate > 5:
            rate_color = "yellow"
        else:
            rate_color = "red"
        
        # Create scan statistics grid
        stats_grid = Table.grid(padding=(0, 1))
        stats_grid.add_column(style="cyan")
        stats_grid.add_column(style="white")
        
        # Add statistics rows
        stats_grid.add_row("Total Paths Scanned:", f"{total_scanned}")
        stats_grid.add_row("Valid Pages Found:", f"[{rate_color}]{valid_found}[/]")
        stats_grid.add_row("Success Rate:", f"[{rate_color}]{success_rate:.2f}%[/]")
        stats_grid.add_row("Total Scan Time:", f"{scan_time:.2f} seconds")
        
        # Add average time metrics
        if total_scanned > 0:
            stats_grid.add_row("Average Time per URL:", f"{(scan_time / total_scanned):.4f} seconds")
            stats_grid.add_row("URLs Processed per Second:", f"{(total_scanned / scan_time):.2f}")
        
        stats_grid.add_row("Scan End Time:", f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Create a summary graph of success rate
        bar_width = 30
        filled_width = int((success_rate / 100) * bar_width)
        success_bar = "█" * filled_width + "░" * (bar_width - filled_width)
        
        # Create performance chart
        stats_chart = Group(
            Text.from_markup(f"\n[bold {rate_color}]Success Rate: {success_rate:.2f}%[/]"),
            Text.from_markup(f"[{rate_color}]{success_bar}[/]")
        )
        
        # Technology statistics
        tech_text = ""
        tech_table = Table(show_header=True, header_style="bold cyan")
        
        if technologies and valid_found > 0:
            # Sort technologies by frequency
            top_techs = sorted(technologies.items(), key=lambda x: x[1], reverse=True)[:10]
            
            tech_table.add_column("Technology")
            tech_table.add_column("Count", style="cyan")
            tech_table.add_column("Percentage", style="cyan")
            tech_table.add_column("Distribution", style="cyan")
            
            for tech, count in top_techs:
                percentage = count / valid_found * 100
                
                # Create a mini bar for the distribution
                mini_bar_width = 10
                filled_chars = int((percentage / 100) * mini_bar_width)
                mini_bar = "█" * filled_chars + "░" * (mini_bar_width - filled_chars)
                
                tech_table.add_row(
                    tech, 
                    str(count), 
                    f"{percentage:.1f}%", 
                    mini_bar
                )
        else:
            tech_text = "[yellow]No technology statistics available.[/]"
            
        # Create the main summary panel
        summary_panel = Panel(
            Group(
                Text.from_markup("[bold cyan]◉ Scan Complete[/]"),
                Text(""),
                Panel(
                    Group(stats_grid, stats_chart),
                    title="[bold cyan]Scan Statistics",
                    border_style="cyan",
                    padding=(1, 1)
                ),
                Panel(
                    tech_table if technologies and valid_found > 0 else Text.from_markup(tech_text),
                    title="[bold green]Technology Detection",
                    border_style="green",
                    padding=(1, 1)
                )
            ),
            title="[bold cyan]Scan Summary Report",
            border_style="cyan",
            padding=(1, 2)
        )
        
        # Print the entire summary
        self.console.print("\n")
        self.console.print(summary_panel)
        self.console.print("\n" + "═" * 80 + "\n")

    def show_progress(self, current: int, total: int, elapsed_time: float):
        """Display real-time progress with statistics in a more organized way"""
        # Calculate progress percentage
        progress_pct = (current / total) * 100 if total > 0 else 0
        
        # Calculate estimated time remaining
        if current > 0:
            avg_time_per_item = elapsed_time / current
            est_time_remaining = avg_time_per_item * (total - current)
            
            # Format remaining time
            if est_time_remaining < 60:
                time_str = f"{est_time_remaining:.1f} seconds"
            elif est_time_remaining < 3600:
                time_str = f"{est_time_remaining / 60:.1f} minutes"
            else:
                time_str = f"{est_time_remaining / 3600:.1f} hours"
                
            # Calculate rate
            rate = current / elapsed_time if elapsed_time > 0 else 0
            rate_str = f"{rate:.1f} paths/sec"
        else:
            time_str = "Calculating..."
            rate_str = "Calculating..."
        
        # Progress bar with improved visuals
        bar_width = 30
        filled_width = int(progress_pct / 100 * bar_width)
        
        # Use different colors based on progress
        if progress_pct < 30:
            bar_color = "bright_red"
        elif progress_pct < 60:
            bar_color = "bright_yellow"
        else:
            bar_color = "bright_green"
            
        bar = "█" * filled_width + "░" * (bar_width - filled_width)
        
        # Create a panel with all progress information
        progress_panel = Panel(
            Group(
                Text.from_markup(f"[cyan]Progress:[/] [bold white]{progress_pct:.1f}%[/] ({current}/{total})"),
                Text("", style="white"),
                Text.from_markup(f"[{bar_color}]{bar}[/]"),
                Text("", style="white"),
                Text.from_markup(f"[cyan]Elapsed:[/] [white]{elapsed_time:.1f}s[/]    [cyan]Remaining:[/] [white]{time_str}[/]"),
                Text.from_markup(f"[cyan]Scan Rate:[/] [white]{rate_str}[/]")
            ),
            title="[bold cyan]Scan Progress",
            border_style="cyan",
            width=80,
            padding=(1, 2)
        )
        
        # Clear previous output and update
        self.console.clear()
        self.console.print(progress_panel)
    
    def show_help(self):
        """Display help information in an organized way"""
        self.clear_screen()
        
        # Create sections
        sections = []
        
        # Usage section
        usage_text = """
[cyan]Basic Usage:[/]
• Start the tool and select an option from the main menu
• Enter a target URL to scan
• Choose scan mode and settings
• View results during and after scan
• Export results in various formats

[cyan]Scan Modes:[/]
• Simple: Basic detection with minimal footprint
• Aggressive: Deep scanning with maximum efficacy
• Stealth: Evasive techniques to avoid detection
"""
        sections.append(Panel(usage_text, title="Usage Guide", border_style="cyan"))
        
        # Command line options
        cmd_text = """
[cyan]Command Line Options:[/]
-u, --url         Target URL to scan
-p, --pathfile    Custom path file (JSON format)
-o, --output      Output file for results
-j, --json        Save results in JSON format
-c, --csv         Save results in CSV format
-h, --html        Save results in HTML format
-q, --quiet       Quiet mode (less output)
--proxy           Use proxy server (e.g., http://127.0.0.1:8080)
--proxy-file      File containing list of proxies
--headless        Use headless browser
--concurrency     Number of concurrent requests
--mode            Scan mode (simple/aggressive/stealth)
"""
        sections.append(Panel(cmd_text, title="Command Line Options", border_style="green"))
        
        # Examples section
        examples_text = """
[cyan]Examples:[/]

1. Basic scan:
   python Finder.py -u https://example.com

2. Aggressive scan with HTML report:
   python Finder.py -u https://example.com --mode aggressive -h

3. Stealth scan with proxy:
   python Finder.py -u https://example.com --mode stealth --proxy http://127.0.0.1:8080

4. Custom paths with multiple output formats:
   python Finder.py -u https://example.com -p custom_paths.json -j -c -h

5. Quiet mode with high concurrency:
   python Finder.py -u https://example.com -q --concurrency 50
"""
        sections.append(Panel(examples_text, title="Examples", border_style="magenta"))
        
        # Create layout
        layout = Layout()
        layout.split_column(*sections)
        
        self.console.print(layout)
        self.console.input("\nPress Enter to continue...")

    def show_warning(self, message: str):
        """Display a warning message in yellow."""
        self.console.print(f"[yellow]{message}[/yellow]")

    def create_progress_bar(self, total: int, description: str = "Scanning...") -> Progress:
        """Create a customized progress bar"""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=None),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TextColumn("•"),
            TimeRemainingColumn(),
            TextColumn("•"),
            TextColumn("Speed: {task.fields[speed]:.2f} paths/sec", justify="right"),
            TextColumn("•"),
            TextColumn("Found: {task.fields[found]}", justify="right"),
            console=Console(force_terminal=True, no_color=False),
            expand=True,
            refresh_per_second=1
        )

    def show_results(self, results: list):
        """Display a list of scan results in compact format"""
        for result in results:
            line = self.show_result(result, compact=True)
            self.console.print(line)

    def show_results_list(self, files: list):
        """Display the list of result files in the results directory"""
        self.console.print("[bold cyan]Previous Scan Results:[/bold cyan]")
        for file in files:
            self.console.print(file)

    # Add this method to TerminalDisplay class to show a cleaner scan completion message
    def show_scan_completion(self, results: List[Dict], scan_time: float, total_scanned: int):
        """Show a nicely formatted scan completion message"""
        # Create a panel with scan statistics
        stats_panel = Panel(
            f"""
[bold green]Scan Complete![/bold green]

[cyan]Total URLs Scanned:[/cyan] {total_scanned}
[cyan]Admin Panels Found:[/cyan] {len(results)}
[cyan]Scan Duration:[/cyan] {scan_time:.2f} seconds
[cyan]Scan Speed:[/cyan] {total_scanned / scan_time:.2f} paths/second

[italic]Results are saved in the results directory[/italic]
        """,
            title="Scan Results Summary",
            border_style="green",
            expand=False
        )
        
        # Print with clear visual separation
        self.console.print("\n" + "═" * 80)
        self.console.print(stats_panel)
        self.console.print("═" * 80 + "\n")
        
        # Notify user about next steps
        self.console.print("[bold cyan]What would you like to do next?[/bold cyan]")
        self.console.print(" • Press Enter to return to the main menu")
        self.console.print(" • Export results in different formats from the main menu")
        self.console.print(" • View detailed results in the saved files\n")

class Scanner:
    def __init__(self, config: Config):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.discovered_urls: Set[str] = set()
        self.scan_start_time: float = 0
        self.found_urls: List[Dict] = []
        self.proxy_manager: Optional[ProxyManager] = None
        self.headless_browser: Optional[HeadlessBrowser] = None
        self.tech_detector = TechnologyDetector()
        # The _setup_logging method is no longer needed as we use the global setup_logging

    async def create_session(self):
        timeout = aiohttp.ClientTimeout(
            total=None,
            connect=self.config.CONNECTION_TIMEOUT,
            sock_read=self.config.READ_TIMEOUT
        )
        connector = aiohttp.TCPConnector(
            ssl=False,
            limit=self.config.MAX_CONCURRENT_TASKS,
            force_close=True,
            enable_cleanup_closed=True
        )
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        )

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": random.choice(self.config.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        # Add extra headers if available
        if hasattr(self.config, 'HEADERS_EXTRA') and self.config.HEADERS_EXTRA:
            headers.update(self.config.HEADERS_EXTRA)
            
        # If in stealth mode, add additional privacy-focused headers
        if hasattr(self.config, 'DETECTION_MODE') and self.config.DETECTION_MODE == 'stealth':
            headers.update({
                "DNT": "1",  # Do Not Track
                "Sec-GPC": "1",  # Global Privacy Control
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document"
            })
            
        return headers

    async def analyze_response(self, response: aiohttp.ClientResponse, url: str, html_content: str = None) -> Dict:
        try:
            if html_content is None:
                html_content = await response.text()
                
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Get meta tags
            meta_tags = {}
            for meta in soup.find_all('meta'):
                if meta.get('name'):
                    meta_tags[meta.get('name')] = meta.get('content', '')
            
            # Get all links
            links = []
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href and not href.startswith(('#', 'javascript:', 'mailto:')):
                    links.append(href)
            
            # Count forms and inputs
            forms = soup.find_all("form")
            inputs = soup.find_all("input")
            
            # Check for login form
            has_login_form = False
            for form in forms:
                # Check if form method is POST (common for login forms)
                if form.get("method", "").lower() == "post":
                    # Check for password fields
                    if form.find("input", {"type": "password"}):
                        has_login_form = True
                        break
                    
                    # Check for login-related keywords in form attributes
                    form_id = form.get("id", "").lower()
                    form_action = form.get("action", "").lower()
                    form_class = form.get("class", [])
                    form_class = " ".join(form_class).lower() if isinstance(form_class, list) else form_class.lower()
                    
                    login_keywords = ["login", "signin", "log-in", "sign-in", "auth", "credential"]
                    if any(keyword in form_id for keyword in login_keywords) or \
                       any(keyword in form_action for keyword in login_keywords) or \
                       any(keyword in form_class for keyword in login_keywords):
                        has_login_form = True
                        break
            
            # Page title
            title = soup.title.string if soup.title else "No Title"
            
            # Detect technologies
            technologies = self.tech_detector.detect_technologies(html_content, dict(response.headers))
            
            # Detect captcha
            has_captcha = self.tech_detector.detect_captcha(html_content)
            
            # Detect web application type
            web_app_type = self.tech_detector.detect_web_application_type(html_content, technologies)
            
            return {
                "status_code": response.status,
                "content_type": response.headers.get("Content-Type", ""),
                "server": response.headers.get("Server", "Unknown"),
                "title": title,
                "forms": len(forms),
                "inputs": len(inputs),
                "has_login_form": has_login_form,
                "technologies": technologies,
                "meta_tags": meta_tags,
                "links_count": len(links),
                "content_length": len(html_content),
                "has_captcha": has_captcha,
                "web_app_type": web_app_type
            }
        except Exception as e:
            logging.error(f"Error analyzing response for {url}: {str(e)}")
            return {
                "status_code": response.status,
                "content_type": "",
                "server": "Unknown",
                "title": "Error",
                "forms": 0,
                "inputs": 0,
                "has_login_form": False,
                "technologies": [],
                "meta_tags": {},
                "links_count": 0,
                "content_length": 0,
                "has_captcha": False,
                "web_app_type": "Unknown"
            }

    def _calculate_confidence(self, analysis: Dict) -> float:
        confidence = 0.0
        
        # Confidence based on response analysis
        if analysis["has_login_form"]:
            confidence += 0.4  # Major factor: presence of login form
            
        if analysis["forms"] > 0:
            confidence += min(0.2, analysis["forms"] * 0.05)  # More forms, higher confidence, up to 0.2
            
        if analysis["inputs"] > 2:
            confidence += min(0.2, analysis["inputs"] * 0.02)  # More inputs, higher confidence, up to 0.2
            
        # More sophisticated technology-based confidence calculation
        if isinstance(analysis["technologies"], dict):
            # Admin interfaces are often built with specific frameworks
            admin_frameworks = ["Laravel", "Django", "Rails", "ASP.NET", "Spring", "Express"]
            cms_platforms = ["WordPress", "Drupal", "Joomla"]
            
            # Check frameworks
            for framework in admin_frameworks:
                if framework in analysis["technologies"].get("frameworks", []):
                    confidence += 0.1
                    break
                    
            # Check CMS platforms
            for cms in cms_platforms:
                if cms in analysis["technologies"].get("cms", []):
                    confidence += 0.15
                    break
                    
            # Security measures often indicate admin areas
            security_count = len(analysis["technologies"].get("security", []))
            if security_count > 0:
                confidence += min(0.15, security_count * 0.03)
        else:
            # Legacy technology detection
            if analysis["technologies"]:
                confidence += min(0.2, len(analysis["technologies"]) * 0.05)
            
        # Confidence based on title and meta tags
        title = analysis.get("title", "").lower()
        admin_terms = ["admin", "administrator", "dashboard", "control", "panel", "login", 
                      "management", "backend", "manage", "cp", "administration"]
        if any(term in title for term in admin_terms):
            confidence += 0.25
            
        # Meta tags can provide additional clues
        meta_tags = analysis.get("meta_tags", {})
        meta_description = meta_tags.get("description", "").lower()
        if any(term in meta_description for term in admin_terms):
            confidence += 0.1
            
        # Check for login-related content length (login pages tend to be smaller)
        if 1000 <= analysis["content_length"] <= 20000:
            confidence += 0.05
            
        # Presence of captcha increases confidence
        if analysis.get("has_captcha", False):
            confidence += 0.2
            
        # Adjust confidence based on web application type
        app_type = analysis.get("web_app_type", "")
        if app_type in ["CMS-based Website", "Blog/CMS"]:
            confidence += 0.1
            
        return min(confidence, 1.0)

    async def scan_url(self, base_url: str, path: str, progress=None, task_id=None) -> Optional[Dict]:
        """Scan a specific URL for admin panel detection"""
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        
        # Execute multiple attempts with exponential backoff
        for attempt in range(self.config.MAX_RETRIES):
            try:
                # Select proxy if enabled
                proxy = None
                if self.config.USE_PROXIES and self.proxy_manager:
                    proxy = self.proxy_manager.get_next_proxy()
                    
                # Use headless browser if enabled
                if self.config.USE_HEADLESS_BROWSER and self.headless_browser:
                    result = await self._scan_with_headless(url, proxy)
                    if result:
                        return result
                
                # Standard scan method
                headers = self._get_headers()  # Get headers with random User-Agent
                
                # Custom timeout for this request
                request_timeout = aiohttp.ClientTimeout(
                    total=self.config.CONNECTION_TIMEOUT + self.config.READ_TIMEOUT,
                    sock_connect=self.config.CONNECTION_TIMEOUT,
                    sock_read=self.config.READ_TIMEOUT
                )
                
                async with self.session.get(url, 
                                          headers=headers, 
                                          proxy=proxy,
                                          allow_redirects=True,
                                          ssl=False,
                                          timeout=request_timeout) as response:
                    
                    # Read content with timeout protection
                    try:
                        content = await asyncio.wait_for(
                            response.text(),
                            timeout=self.config.READ_TIMEOUT
                        )
                    except asyncio.TimeoutError:
                        logging.warning(f"Content read timeout for {url}")
                        raise  # Re-raise for retry handling
                    
                    # Analyze response
                    analysis = await self.analyze_response(response, url, content)
                    
                    # Update proxy status if successful
                    if proxy and self.proxy_manager:
                        self.proxy_manager.update_proxy_health(proxy, True)
                    
                    # Don't return results for unimportant pages
                    if analysis and analysis.get('confidence', 0) > 0:
                        self.found_urls.append(analysis)
                        return analysis
                        
                    return None
                    
            except asyncio.TimeoutError:
                # Exponential backoff with jitter between attempts
                delay = self.config.RETRY_DELAY * (self.config.TIMEOUT_BACKOFF_FACTOR ** attempt) + (random.random() * self.config.RETRY_JITTER)
                logging.warning(f"Timeout error on {url}, retrying in {delay:.2f}s (attempt {attempt+1}/{self.config.MAX_RETRIES})")
                
                # Update proxy status if it failed
                if proxy and self.proxy_manager:
                    self.proxy_manager.update_proxy_health(proxy, False)
                    
                await asyncio.sleep(delay)
                continue
                
            except Exception as e:
                # Update proxy status if it failed
                if proxy and self.proxy_manager:
                    self.proxy_manager.update_proxy_health(proxy, False)
                    
                error_msg = str(e).strip()
                logging.error(f"Error scanning {url}: {error_msg}")
                return None
                
        # If we reached here, all attempts failed
        logging.error(f"All retry attempts failed for {url}")
        return None
        
    async def _scan_with_headless(self, url: str, proxy: Optional[str] = None) -> Optional[Dict]:
        """Scan URL using headless browser for more accurate detection"""
        if not self.headless_browser:
            return None
            
        try:
            # Visit the page with headless browser
            result = await self.headless_browser.visit_page(url, proxy)
            
            if result.get("success", False) and result.get("status", 0) < 500:
                # Calculate confidence based on browser analysis
                confidence = 0.0
                
                # Check for login form
                if result.get("has_login_form", False):
                    confidence += 0.4
                    
                # Check form details
                form_details = result.get("form_details", [])
                login_form_detected = False
                for form in form_details:
                    # Check for password inputs
                    has_password = any(input_el.get("type") == "password" for input_el in form.get("inputs", []))
                    if has_password:
                        login_form_detected = True
                        break
                        
                    # Check form action for login-related keywords
                    action = form.get("action", "").lower()
                    login_keywords = ["login", "signin", "auth", "authenticate", "log-in", "sign-in"]
                    if any(keyword in action for keyword in login_keywords):
                        login_form_detected = True
                        break
                
                if login_form_detected:
                    confidence += 0.3
                    
                # Check for captcha
                if result.get("has_captcha", False):
                    confidence += 0.2
                    
                # Check title
                title = result.get("title", "").lower()
                admin_terms = ["admin", "administrator", "dashboard", "control", "panel", "login", 
                              "management", "backend", "manage", "cp", "administration"]
                if any(term in title for term in admin_terms):
                    confidence += 0.25
                    
                # Check technologies
                technologies = result.get("technologies", {})
                if technologies:
                    # Admin interfaces are often built with specific frameworks
                    admin_frameworks = ["Laravel", "Django", "Rails", "ASP.NET", "Spring", "Express"]
                    cms_platforms = ["WordPress", "Drupal", "Joomla"]
                    
                    # Check frameworks
                    for framework in admin_frameworks:
                        if framework in technologies.get("frameworks", []):
                            confidence += 0.1
                            break
                            
                    # Check CMS platforms
                    for cms in cms_platforms:
                        if cms in technologies.get("cms", []):
                            confidence += 0.15
                            break
                            
                    # Security measures often indicate admin areas
                    security_count = len(technologies.get("security", []))
                    if security_count > 0:
                        confidence += min(0.15, security_count * 0.03)
                
                confidence = min(confidence, 1.0)
                
                response_time = result.get("elapsed_time", 0)
                if response_time == 0:
                    response_time = 0.5  # Default if not provided
                
                # Build result for standard format
                scan_result = {
                    "url": url,
                    "path": url.split("/")[-1] if "/" in url else "",
                    "is_valid": True,
                    "status_code": result.get("status", 200),
                    "response_time": response_time,
                    "confidence": confidence,
                    "server": "Unknown",  # Headless browser may not capture this
                    "title": result.get("title", ""),
                    "forms": len(result.get("form_details", [])),
                    "inputs": sum(len(form.get("inputs", [])) for form in result.get("form_details", [])),
                    "has_login_form": login_form_detected,
                    "technologies": result.get("technologies", {}),
                    "has_captcha": result.get("has_captcha", False),
                    "content_length": len(result.get("html", "")),
                    "proxy_used": proxy is not None,
                    "headless_used": True,
                    "web_app_type": "Unknown"  # Would require additional processing
                }
                
                if confidence > 0.3:  # Only consider if confidence is reasonable
                    self.found_urls.append(scan_result)
                    return scan_result
                    
            return None
        except Exception as e:
            logging.error(f"Error in headless scan for {url}: {str(e)}")
            return None

    async def _process_batch(self, url: str, batch: List[str], progress=None, task_id=None) -> List[Dict]:
        """Process a batch of paths with dynamic concurrency adjustment"""
        results = []
        tasks = []
        timeout_count = 0
        
        # Determine initial concurrency based on detection mode
        concurrency = self.config.MAX_CONCURRENT_TASKS
        if self.config.DETECTION_MODE == 'stealth':
            concurrency = min(concurrency, 10)  # Lower in stealth mode
        
        # Create a semaphore with initial concurrency
        sem = asyncio.Semaphore(concurrency)
        
        # Helper function to scan with semaphore
        async def scan_with_sem(path):
            nonlocal timeout_count
            async with sem:
                try:
                    result = await self.scan_url(url, path, progress, task_id)
                    if result:
                        results.append(result)
                        if progress:
                            progress.update(task_id, advance=1, found=len(results))
                    else:
                        if progress:
                            progress.update(task_id, advance=1)
                    return result
                except asyncio.TimeoutError:
                    timeout_count += 1
                    
                    # Dynamically adjust concurrency based on timeout frequency
                    if self.config.AUTO_ADJUST_CONCURRENCY and timeout_count > self.config.MAX_TIMEOUT_THRESHOLD:
                        # Get current limit of the semaphore
                        current_limit = sem._value
                        
                        # Calculate new limit (reduce by half but min of 3)
                        new_limit = max(3, current_limit // 2)
                        
                        if new_limit < current_limit:
                            logging.warning(f"Too many timeouts ({timeout_count}), reducing concurrency from {current_limit} to {new_limit}")
                            
                            # Create a new semaphore with reduced limit
                            # (we can't directly modify the value of existing semaphore)
                            new_sem = asyncio.Semaphore(new_limit)
                            sem._value = new_limit  # This is a hack but works for our purpose
                            
                            # Reset timeout counter after adjustment
                            timeout_count = 0
                    
                    if progress:
                        progress.update(task_id, advance=1)
                    return None
                
                except Exception as e:
                    logging.error(f"Error in scan_with_sem for {url}/{path}: {str(e)}")
                    if progress:
                        progress.update(task_id, advance=1)
                    return None
        
        # Create tasks for all paths
        for path in batch:
            tasks.append(scan_with_sem(path))
        
        # Execute all tasks
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return results

    async def scan(self, url: str, paths: List[str], concurrency: int = None) -> List[Dict]:
        """Scan a URL with multiple paths for admin panels"""
        # Initialize the session if not already done
        if not self.session:
            logging.info("Creating a new session for scanning")
            await self.create_session()
        else:
            # Check if session is closed and create a new one if needed
            if self.session.closed:
                logging.info("Previous session was closed, creating a new one")
                await self.create_session()
            
        # Initialize headless browser if enabled
        if self.config.USE_HEADLESS_BROWSER and not self.headless_browser:
            self.headless_browser = HeadlessBrowser(self.config)
            await self.headless_browser.initialize()
            
        # Initialize proxy manager if needed
        if self.config.USE_PROXIES and not self.proxy_manager:
            self.proxy_manager = ProxyManager(self.config)
            
        # Record the start time
        self.scan_start_time = time.time()
        self.found_urls = []
        
        # Setup adaptive batch size based on detection mode
        batch_size = self.config.BATCH_SIZE
        if self.config.DETECTION_MODE == 'stealth':
            batch_size = max(5, batch_size // 3)  # Smaller batches in stealth mode
        elif self.config.DETECTION_MODE == 'aggressive':
            batch_size = min(batch_size * 2, 50)  # Larger batches in aggressive mode
            
        # Use the Rich library for progress display
        with console.status(f"Preparing to scan {url} with {len(paths)} paths...", spinner="dots") as status:
            # Check URL reachability before starting full scan
            try:
                async with self.session.get(url, headers=self._get_headers(), timeout=aiohttp.ClientTimeout(total=self.config.CONNECTION_TIMEOUT * 2)) as response:
                    if response.status >= 400:
                        logging.warning(f"Target URL {url} returned status code {response.status}")
                        console.print(f"[yellow]Warning: Target URL {url} returned status code {response.status}[/yellow]")
                        if response.status == 403:
                            console.print(f"[yellow]This may indicate the site is blocking automated requests or has WAF protection.[/yellow]")
                        elif response.status == 404:
                            console.print(f"[yellow]This may indicate the URL does not exist. Please check the URL and try again.[/yellow]")
                        elif response.status == 429:
                            console.print(f"[yellow]Rate limiting detected. Consider using stealth mode or adding delays between requests.[/yellow]")
                        elif response.status >= 500:
                            console.print(f"[yellow]Server error detected. The target server may be experiencing issues.[/yellow]")
            except aiohttp.ClientConnectorError as e:
                logging.error(f"Connection error to target URL {url}: {str(e)}")
                console.print(f"[red]Connection error: Failed to connect to {url}[/red]")
                console.print(f"[yellow]Possible causes:[/yellow]")
                console.print(f"[yellow]• The domain does not exist or cannot be resolved[/yellow]")
                console.print(f"[yellow]• Your internet connection is down or unstable[/yellow]")
                console.print(f"[yellow]• The target server is offline or unreachable[/yellow]")
                return []
            except aiohttp.ClientSSLError as e:
                logging.error(f"SSL error when connecting to {url}: {str(e)}")
                console.print(f"[red]SSL Error: Certificate verification failed for {url}[/red]")
                console.print(f"[yellow]You can try disabling SSL verification in settings.[/yellow]")
                return []
            except aiohttp.ClientTimeout as e:
                logging.error(f"Timeout when connecting to {url}: {str(e)}")
                console.print(f"[red]Timeout: The connection to {url} timed out[/red]")
                console.print(f"[yellow]Try increasing the connection timeout in settings.[/yellow]")
                return []
            except Exception as e:
                logging.error(f"Failed to reach target URL {url}: {str(e)}")
                console.print(f"[red]Error: Failed to reach target URL {url}: {str(e)}[/red]")
                return []
                
            # Create batches of paths
            batches = [paths[i:i + batch_size] for i in range(0, len(paths), batch_size)]
            logging.info(f"Starting scan of {url} with {len(paths)} paths in {len(batches)} batches")
            
            # Create progress bar
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("({task.completed}/{task.total})"),
                TextColumn("•"),
                TimeRemainingColumn(),
                TextColumn("•"),
                TextColumn("Speed: {task.fields[speed]:.2f} paths/sec", justify="right"),
                TextColumn("•"),
                TextColumn("Found: {task.fields[found]}", justify="right"),
                console=console,
                expand=True
            )
        
        with progress:
            # Add main task to progress bar
            task_id = progress.add_task("Scanning...", total=len(paths), speed=0, found=0)
            
            results = []
            start_time = time.time()
            completed = 0
            
            # Process batches with dynamic adjustment
            for i, batch in enumerate(batches):
                batch_results = await self._process_batch(url, batch, progress, task_id)
                results.extend(batch_results)
                
                # Update speed calculation
                completed += len(batch)
                elapsed = time.time() - start_time
                speed = completed / elapsed if elapsed > 0 else 0
                progress.update(task_id, speed=speed)
                
                # Adaptive delay between batches based on detection mode
                if self.config.DETECTION_MODE == 'stealth':
                    delay = random.uniform(0.5, 2.0)  # Random delay in stealth mode
                    await asyncio.sleep(delay)
            
            # Return found URLs
            return self.found_urls

    async def cleanup(self):
        """Close the session and release resources"""
        if self.session:
            await self.session.close()
            self.session = None
            
        if self.headless_browser:
            await self.headless_browser.close()
            self.headless_browser = None
            
        logging.info("Scanner resources cleaned up successfully")

class ResultExporter:
    """Exports scan results in various formats"""
    
    def __init__(self, config: 'Config'):
        self.config = config
        
    def export_results(self, results: List[Dict], scan_info: Dict, format_type: str, filepath: str) -> bool:
        """Export results in the specified format"""
        if format_type == "txt":
            return self._export_txt(results, scan_info, filepath)
        elif format_type == "json":
            return self._export_json(results, scan_info, filepath)
        elif format_type == "csv":
            return self._export_csv(results, scan_info, filepath)
        elif format_type == "html":
            return self._export_html(results, scan_info, filepath)
        else:
            logging.error(f"Unsupported export format: {format_type}")
            return False
    
    def _export_txt(self, results: List[Dict], scan_info: Dict, filepath: str) -> bool:
        """Export results in plain text format"""
        try:
            with open(f"{filepath}.txt", "w", encoding="utf-8") as f:
                f.write(f"Scan Report - {scan_info['scan_date']}\n")
                f.write(f"Target URL: {scan_info['target_url']}\n")
                f.write(f"Scan Mode: {scan_info.get('scan_mode', 'standard')}\n")
                f.write(f"Total Paths: {scan_info['total_paths']}\n")
                f.write(f"Valid Pages: {scan_info['valid_pages']}\n")
                f.write(f"Scan Time: {scan_info['scan_time']} seconds\n")
                f.write("=" * 50 + "\n\n")
                
                for result in results:
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Status Code: {result['status_code']}\n")
                    f.write(f"Response Time: {result['response_time']:.2f}s\n")
                    f.write(f"Server: {result['server']}\n")
                    f.write(f"Title: {result.get('title', 'N/A')}\n")
                    
                    # Write technologies by category if available
                    if isinstance(result.get('technologies'), dict):
                        for category, techs in result['technologies'].items():
                            if techs:
                                f.write(f"{category.title()}: {', '.join(techs)}\n")
                    else:
                        f.write(f"Technologies: {', '.join(result.get('technologies', []))}\n")
                        
                    f.write(f"Forms Found: {result['forms']}\n")
                    f.write(f"Input Fields: {result.get('inputs', 0)}\n")
                    f.write(f"Login Form: {'Yes' if result['has_login_form'] else 'No'}\n")
                    f.write(f"CAPTCHA Detected: {'Yes' if result.get('has_captcha', False) else 'No'}\n")
                    f.write(f"Confidence: {result['confidence']*100:.1f}%\n")
                    f.write("\n" + "=" * 50 + "\n")
                
                return True
        except Exception as e:
            logging.error(f"Error exporting to TXT: {str(e)}")
            return False
    
    def _export_json(self, results: List[Dict], scan_info: Dict, filepath: str) -> bool:
        """Export results in JSON format"""
        try:
            # Clean up results for JSON serialization
            clean_results = []
            for result in results:
                # Create a clean copy without non-serializable objects
                clean_result = {k: v for k, v in result.items() if not isinstance(v, (bytes, bytearray))}
                
                # Handle screenshots specially
                if "screenshots" in result:
                    clean_result["screenshots"] = [
                        {"format": s["format"]} for s in result.get("screenshots", [])
                    ]
                
                clean_results.append(clean_result)
            
            json_data = {
                "scan_info": scan_info,
                "results": clean_results
            }
            
            with open(f"{filepath}.json", "w", encoding="utf-8") as f:
                json.dump(json_data, f, indent=4)
                
            return True
        except Exception as e:
            logging.error(f"Error exporting to JSON: {str(e)}")
            return False
    
    def _export_csv(self, results: List[Dict], scan_info: Dict, filepath: str) -> bool:
        """Export results in CSV format"""
        try:
            with open(f"{filepath}.csv", "w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    "URL", "Status", "Response Time (s)", "Server", "Title",
                    "Forms", "Inputs", "Login Form", "CAPTCHA", "Technologies",
                    "Confidence (%)", "Web Application Type"
                ])
                
                # Write data rows
                for result in results:
                    # Format technologies
                    if isinstance(result.get('technologies'), dict):
                        techs = []
                        for category, tech_list in result['technologies'].items():
                            techs.extend(tech_list)
                        technologies = "; ".join(techs)
                    else:
                        technologies = "; ".join(result.get('technologies', []))
                    
                    writer.writerow([
                        result['url'],
                        result['status_code'],
                        f"{result['response_time']:.2f}",
                        result['server'],
                        result.get('title', 'N/A'),
                        result['forms'],
                        result.get('inputs', 0),
                        'Yes' if result['has_login_form'] else 'No',
                        'Yes' if result.get('has_captcha', False) else 'No',
                        technologies,
                        f"{result['confidence']*100:.1f}",
                        result.get('web_app_type', 'Unknown')
                    ])
                
                return True
        except Exception as e:
            logging.error(f"Error exporting to CSV: {str(e)}")
            return False
    
    def _export_html(self, results: List[Dict], scan_info: Dict, filepath: str) -> bool:
        """Export results in HTML format with interactive features"""
        try:
            # Count technologies
            tech_count = {}
            for result in results:
                if isinstance(result.get('technologies'), dict):
                    for category, techs in result['technologies'].items():
                        for tech in techs:
                            tech_count[tech] = tech_count.get(tech, 0) + 1
                else:
                    for tech in result.get('technologies', []):
                        tech_count[tech] = tech_count.get(tech, 0) + 1
            
            # Sort technologies by count
            sorted_techs = sorted(tech_count.items(), key=lambda x: x[1], reverse=True)
            
            # Create HTML content
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Report - {scan_info['target_url']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .summary {{ display: flex; justify-content: space-between; margin-bottom: 20px; }}
        .summary-box {{ background-color: white; border-radius: 5px; padding: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); flex: 1; margin: 0 10px; }}
        .result-card {{ background-color: white; border-radius: 5px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .high-confidence {{ border-left: 5px solid #27ae60; }}
        .medium-confidence {{ border-left: 5px solid #f39c12; }}
        .low-confidence {{ border-left: 5px solid #e74c3c; }}
        .tech-tag {{ display: inline-block; background-color: #3498db; color: white; padding: 3px 8px; border-radius: 3px; margin: 2px; font-size: 12px; }}
        .status-200 {{ color: #27ae60; }}
        .status-300 {{ color: #3498db; }}
        .status-400 {{ color: #e74c3c; }}
        .status-500 {{ color: #c0392b; }}
        .chart {{ height: 250px; margin-bottom: 20px; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #2c3e50; color: white; }}
        tr:hover {{ background-color: #f1f1f1; }}
        .filters {{ margin-bottom: 20px; }}
        .filters select, .filters input {{ padding: 8px; margin-right: 10px; border-radius: 4px; border: 1px solid #ddd; }}
        .filters button {{ padding: 8px 15px; background-color: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; }}
        .tab {{ overflow: hidden; background-color: #f1f1f1; border-radius: 5px 5px 0 0; }}
        .tab button {{ background-color: inherit; float: left; border: none; outline: none; cursor: pointer; padding: 14px 16px; }}
        .tab button:hover {{ background-color: #ddd; }}
        .tab button.active {{ background-color: #2c3e50; color: white; }}
        .tabcontent {{ display: none; padding: 20px; background-color: white; border-radius: 0 0 5px 5px; }}
        #dashboard {{ display: block; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Scan Report</h1>
            <p>Target: {scan_info['target_url']}</p>
            <p>Date: {scan_info['scan_date']}</p>
        </div>
        
        <div class="tab">
            <button class="tablinks active" onclick="openTab(event, 'dashboard')">Dashboard</button>
            <button class="tablinks" onclick="openTab(event, 'results')">Results</button>
            <button class="tablinks" onclick="openTab(event, 'technologies')">Technologies</button>
            <button class="tablinks" onclick="openTab(event, 'security')">Security</button>
        </div>
        
        <div id="dashboard" class="tabcontent">
            <div class="summary">
                <div class="summary-box">
                    <h3>Scan Summary</h3>
                    <p>Total Paths: {scan_info['total_paths']}</p>
                    <p>Valid Pages: {scan_info['valid_pages']}</p>
                    <p>Success Rate: {(scan_info['valid_pages'] / scan_info['total_paths'] * 100):.1f}%</p>
                    <p>Scan Time: {scan_info['scan_time']:.2f} seconds</p>
                </div>
                <div class="summary-box">
                    <h3>Status Codes</h3>
                    <canvas id="statusChart"></canvas>
                </div>
                <div class="summary-box">
                    <h3>Technologies</h3>
                    <canvas id="techChart"></canvas>
                </div>
            </div>
            
            <h3>Admin Panels Found</h3>
            <table>
                <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>Confidence</th>
                    <th>Login Form</th>
                </tr>
"""
            
            # Add top 10 results (highest confidence)
            top_results = sorted(results, key=lambda x: x['confidence'], reverse=True)[:10]
            for result in top_results:
                status_class = ""
                if 200 <= result['status_code'] < 300:
                    status_class = "status-200"
                elif 300 <= result['status_code'] < 400:
                    status_class = "status-300"
                elif 400 <= result['status_code'] < 500:
                    status_class = "status-400"
                else:
                    status_class = "status-500"
                    
                html_content += f"""
                <tr>
                    <td><a href="{result['url']}" target="_blank">{result['url']}</a></td>
                    <td class="{status_class}">{result['status_code']}</td>
                    <td>{result['confidence']*100:.1f}%</td>
                    <td>{'Yes' if result['has_login_form'] else 'No'}</td>
                </tr>"""
            
            # Add chart initialization for status codes
            status_counts = {}
            for result in results:
                status_group = f"{result['status_code'] // 100}xx"
                status_counts[status_group] = status_counts.get(status_group, 0) + 1
            
            tech_data = [{"name": name, "count": count} for name, count in sorted_techs[:10]]
            
            html_content += f"""
            </table>
        </div>
        
        <div id="results" class="tabcontent">
            <div class="filters">
                <input type="text" id="urlFilter" placeholder="Filter by URL">
                <select id="statusFilter">
                    <option value="">All Status Codes</option>
                    <option value="2xx">2xx Success</option>
                    <option value="3xx">3xx Redirection</option>
                    <option value="4xx">4xx Client Error</option>
                    <option value="5xx">5xx Server Error</option>
                </select>
                <select id="confidenceFilter">
                    <option value="">All Confidence</option>
                    <option value="high">High (70-100%)</option>
                    <option value="medium">Medium (40-69%)</option>
                    <option value="low">Low (0-39%)</option>
                </select>
                <button onclick="applyFilters()">Apply Filters</button>
            </div>
            
            <div id="resultsList">
"""
            
            # Add all results
            for result in results:
                confidence_class = ""
                if result['confidence'] >= 0.7:
                    confidence_class = "high-confidence"
                elif result['confidence'] >= 0.4:
                    confidence_class = "medium-confidence"
                else:
                    confidence_class = "low-confidence"
                    
                status_class = ""
                if 200 <= result['status_code'] < 300:
                    status_class = "status-200"
                elif 300 <= result['status_code'] < 400:
                    status_class = "status-300"
                elif 400 <= result['status_code'] < 500:
                    status_class = "status-400"
                else:
                    status_class = "status-500"
                
                # Format technologies
                tech_html = ""
                if isinstance(result.get('technologies'), dict):
                    for category, techs in result['technologies'].items():
                        if techs:
                            for tech in techs:
                                tech_html += f'<span class="tech-tag">{tech}</span>'
                else:
                    for tech in result.get('technologies', []):
                        tech_html += f'<span class="tech-tag">{tech}</span>'
                
                html_content += f"""
                <div class="result-card {confidence_class}" data-url="{result['url']}" 
                     data-status="{result['status_code'] // 100}xx" 
                     data-confidence="{'high' if result['confidence'] >= 0.7 else 'medium' if result['confidence'] >= 0.4 else 'low'}">
                    <h3><a href="{result['url']}" target="_blank">{result['url']}</a></h3>
                    <p>Status: <span class="{status_class}">{result['status_code']}</span> | 
                       Response Time: {result['response_time']:.2f}s | 
                       Confidence: {result['confidence']*100:.1f}%</p>
                    <p>Server: {result['server']}</p>
                    <p>Title: {result.get('title', 'N/A')}</p>
                    <p>Forms: {result['forms']} | 
                       Inputs: {result.get('inputs', 0)} | 
                       Login Form: {'Yes' if result['has_login_form'] else 'No'} |
                       CAPTCHA: {'Yes' if result.get('has_captcha', False) else 'No'}</p>
                    <div>
                        <p>Technologies:</p>
                        {tech_html}
                    </div>
                </div>"""
            
            html_content += f"""
            </div>
        </div>
        
        <div id="technologies" class="tabcontent">
            <div class="chart">
                <canvas id="techBarChart"></canvas>
            </div>
            
            <h3>Detected Technologies</h3>
            <table>
                <tr>
                    <th>Technology</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
"""
            
            # Add technology stats
            for tech, count in sorted_techs:
                percentage = count / len(results) * 100
                html_content += f"""
                <tr>
                    <td>{tech}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>"""
            
            html_content += f"""
            </table>
        </div>
        
        <div id="security" class="tabcontent">
            <h3>Security Overview</h3>
            <div class="summary">
                <div class="summary-box">
                    <h3>Login Forms</h3>
                    <p>Pages with Login: {sum(1 for r in results if r['has_login_form'])}</p>
                    <p>Percentage: {sum(1 for r in results if r['has_login_form']) / len(results) * 100:.1f}%</p>
                </div>
                <div class="summary-box">
                    <h3>CAPTCHA</h3>
                    <p>Pages with CAPTCHA: {sum(1 for r in results if r.get('has_captcha', False))}</p>
                    <p>Percentage: {sum(1 for r in results if r.get('has_captcha', False)) / len(results) * 100:.1f}%</p>
                </div>
                <div class="summary-box">
                    <h3>Security Headers</h3>
                    <canvas id="securityChart"></canvas>
                </div>
            </div>
            
            <h3>Security Headers</h3>
            <table>
                <tr>
                    <th>Header</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
"""
            
            # Collect security headers data
            security_headers = [
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-XSS-Protection",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Feature-Policy",
                "Permissions-Policy"
            ]
            
            header_counts = {}
            for header in security_headers:
                header_counts[header] = 0
            
            # Count security headers
            for result in results:
                if isinstance(result.get('technologies'), dict) and 'security' in result['technologies']:
                    for tech in result['technologies']['security']:
                        for header in security_headers:
                            if header in tech:
                                header_counts[header] += 1
            
            # Add security headers stats
            for header, count in header_counts.items():
                percentage = count / len(results) * 100 if results else 0
                html_content += f"""
                <tr>
                    <td>{header}</td>
                    <td>{count}</td>
                    <td>{percentage:.1f}%</td>
                </tr>"""
            
            html_content += f"""
            </table>
        </div>
    
        <script>
            // Initialize charts
            window.onload = function() {{
                // Status code chart
                const statusCtx = document.getElementById('statusChart').getContext('2d');
                const statusChart = new Chart(statusCtx, {{
                    type: 'pie',
                    data: {{
                        labels: {list(status_counts.keys())},
                        datasets: [{{
                            data: {list(status_counts.values())},
                            backgroundColor: ['#27ae60', '#3498db', '#e74c3c', '#c0392b']
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        plugins: {{
                            legend: {{
                                position: 'right'
                            }}
                        }}
                    }}
                }});
                
                // Technology chart
                const techCtx = document.getElementById('techChart').getContext('2d');
                const techChart = new Chart(techCtx, {{
                    type: 'doughnut',
                    data: {{
                        labels: {[item["name"] for item in tech_data]},
                        datasets: [{{
                            data: {[item["count"] for item in tech_data]},
                            backgroundColor: [
                                '#3498db', '#2ecc71', '#9b59b6', '#e74c3c', '#f1c40f', 
                                '#1abc9c', '#e67e22', '#34495e', '#16a085', '#d35400'
                            ]
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        plugins: {{
                            legend: {{
                                position: 'right'
                            }}
                        }}
                    }}
                }});
                
                // Tech bar chart
                const techBarCtx = document.getElementById('techBarChart').getContext('2d');
                const techBarChart = new Chart(techBarCtx, {{
                    type: 'bar',
                    data: {{
                        labels: {[item["name"] for item in tech_data]},
                        datasets: [{{
                            label: 'Technology Usage',
                            data: {[item["count"] for item in tech_data]},
                            backgroundColor: '#3498db'
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        plugins: {{
                            legend: {{
                                display: false
                            }}
                        }},
                        scales: {{
                            y: {{
                                beginAtZero: true,
                                title: {{
                                    display: true,
                                    text: 'Count'
                                }}
                            }}
                        }}
                    }}
                }});
                
                // Security chart
                const securityCtx = document.getElementById('securityChart').getContext('2d');
                const securityChart = new Chart(securityCtx, {{
                    type: 'bar',
                    data: {{
                        labels: {list(header_counts.keys())},
                        datasets: [{{
                            label: 'Security Headers',
                            data: {list(header_counts.values())},
                            backgroundColor: '#e74c3c'
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        indexAxis: 'y',
                        plugins: {{
                            legend: {{
                                display: false
                            }}
                        }},
                        scales: {{
                            x: {{
                                beginAtZero: true
                            }}
                        }}
                    }}
                }});
            }};
            
            // Tab functionality
            function openTab(evt, tabName) {{
                const tabcontent = document.getElementsByClassName("tabcontent");
                for (let i = 0; i < tabcontent.length; i++) {{
                    tabcontent[i].style.display = "none";
                }}
                
                const tablinks = document.getElementsByClassName("tablinks");
                for (let i = 0; i < tablinks.length; i++) {{
                    tablinks[i].className = tablinks[i].className.replace(" active", "");
                }}
                
                document.getElementById(tabName).style.display = "block";
                evt.currentTarget.className += " active";
            }}
            
            // Filter functionality
            function applyFilters() {{
                const urlFilter = document.getElementById('urlFilter').value.toLowerCase();
                const statusFilter = document.getElementById('statusFilter').value;
                const confidenceFilter = document.getElementById('confidenceFilter').value;
                
                const resultCards = document.querySelectorAll('.result-card');
                
                resultCards.forEach(card => {{
                    const url = card.getAttribute('data-url').toLowerCase();
                    const status = card.getAttribute('data-status');
                    const confidence = card.getAttribute('data-confidence');
                    
                    let display = true;
                    
                    if (urlFilter && !url.includes(urlFilter)) {{
                        display = false;
                    }}
                    
                    if (statusFilter && status !== statusFilter) {{
                        display = false;
                    }}
                    
                    if (confidenceFilter && confidence !== confidenceFilter) {{
                        display = false;
                    }}
                    
                    card.style.display = display ? 'block' : 'none';
                }});
            }}
        </script>
    </div>
</body>
</html>
"""
            
            with open(f"{filepath}.html", "w", encoding="utf-8") as f:
                f.write(html_content)
                
            return True
        except Exception as e:
            logging.error(f"Error exporting to HTML: {str(e)}")
            return False

class TechnologyDetector:
    """Class for detecting technologies used in web applications"""
    
    def __init__(self):
        self.tech_signatures = {
            "wordpress": ["wp-content", "wp-includes", "wp-admin"],
            "drupal": ["drupal", "sites/all", "drupal.org"],
            "joomla": ["joomla", "com_content", "com_users"],
            "laravel": ["laravel", "csrf-token", "laravel.com"],
            "django": ["csrfmiddlewaretoken", "django", "dsn"],
            "react": ["react", "react-dom", "reactjs"],
            "vue": ["vue.js", "vuejs", "vue-router"],
            "bootstrap": ["bootstrap.min.css", "bootstrap.min.js", "bootstrap-"],
            "jquery": ["jquery.min.js", "jquery-", "jquery.com"],
            "php": ["php", ".php", "php-"],
            "asp.net": ["__viewstate", "asp.net", ".aspx"],
            "nodejs": ["node_modules", "express", "nodejs"],
            "angularjs": ["ng-", "angular", "angularjs"],
            "ruby": ["rails", "ruby", "gems"],
            "java": ["java", "jsessionid", "servlet"]
        }
        
        self.security_headers = [
            "X-XSS-Protection",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Strict-Transport-Security",
            "Referrer-Policy",
            "Feature-Policy",
            "Permissions-Policy"
        ]
    
    def detect_technologies(self, html: str, headers: Dict) -> List[str]:
        """Detect technologies used in a web page based on HTML and headers"""
        technologies = []
        html_lower = html.lower()
        
        # Check known technology signatures
        for tech, signatures in self.tech_signatures.items():
            if any(sig in html_lower for sig in signatures):
                technologies.append(tech.title())
        
        # Detect server technologies
        server = headers.get("Server", "").lower()
        if "apache" in server:
            technologies.append("Apache")
        if "nginx" in server:
            technologies.append("Nginx")
        if "microsoft-iis" in server:
            technologies.append("IIS")
        if "cloudflare" in server:
            technologies.append("Cloudflare")
        
        # Check for security headers
        for header in self.security_headers:
            if header in headers:
                technologies.append(f"{header.replace('-', ' ')}")
                
        return list(set(technologies))
    
    def detect_captcha(self, html: str) -> bool:
        """Detect if a page contains CAPTCHA protection"""
        html_lower = html.lower()
        
        # Common CAPTCHA signatures
        captcha_signatures = [
            "captcha",
            "recaptcha",
            "g-recaptcha",
            "hcaptcha",
            "turnstile",
            "cf-turnstile",
            "are you a human",
            "bot protection",
            "robot verification",
            "complete the security check"
        ]
        
        # Check for CAPTCHA in HTML
        if any(sig in html_lower for sig in captcha_signatures):
            return True
            
        # Check for CAPTCHA related JavaScript
        captcha_js = [
            "grecaptcha",
            "hcaptcha.render",
            "recaptcha",
            "captcha.js",
            "turnstile.render"
        ]
        
        if any(sig in html_lower for sig in captcha_js):
            return True
            
        # Check for CAPTCHA images
        if "captcha" in html_lower and ("image" in html_lower or "img" in html_lower):
            return True
            
        return False
    
    def detect_web_application_type(self, html: str, technologies: List[str]) -> str:
        """Detect the type of web application"""
        html_lower = html.lower()
        
        # Check for CMS first
        cms = self.detect_cms(html)
        if cms:
            return f"{cms} CMS"
            
        # Check for framework
        framework = self.detect_framework(html)
        if framework:
            return f"{framework} App"
            
        # Check for common admin panel indicators
        admin_indicators = [
            "admin dashboard", 
            "control panel",
            "administration",
            "backend system",
            "management console"
        ]
        
        for indicator in admin_indicators:
            if indicator in html_lower:
                return "Admin Interface"
                
        # Check for login page
        login_indicators = [
            "login page",
            "sign in",
            "log in",
            "authentication"
        ]
        
        for indicator in login_indicators:
            if indicator in html_lower:
                return "Login Portal"
                
        # Default if no specific type detected
        return "Generic Web App"
    
    def detect_cms(self, html: str) -> Optional[str]:
        """Specifically detect content management systems"""
        html_lower = html.lower()
        
        if any(sig in html_lower for sig in self.tech_signatures["wordpress"]):
            return "WordPress"
        if any(sig in html_lower for sig in self.tech_signatures["drupal"]):
            return "Drupal"
        if any(sig in html_lower for sig in self.tech_signatures["joomla"]):
            return "Joomla"
            
        return None
    
    def detect_framework(self, html: str) -> Optional[str]:
        """Specifically detect web frameworks"""
        html_lower = html.lower()
        
        if any(sig in html_lower for sig in self.tech_signatures["laravel"]):
            return "Laravel"
        if any(sig in html_lower for sig in self.tech_signatures["django"]):
            return "Django"
        if any(sig in html_lower for sig in self.tech_signatures["react"]):
            return "React"
        
        return None

class HeadlessBrowser:
    """Class for headless browser-based scanning"""
    
    def __init__(self, config: Config):
        self.config = config
        self.browser = None
        self.page = None
        self.initialized = False
    
    async def initialize(self):
        """Initialize the headless browser"""
        try:
            from playwright.async_api import async_playwright
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=True)
            self.context = await self.browser.new_context(
                user_agent=random.choice(self.config.USER_AGENTS),
                viewport={"width": 1280, "height": 720}
            )
            self.page = await self.context.new_page()
            self.initialized = True
            logging.info("Headless browser initialized successfully")
            return True
        except ImportError:
            error_msg = "Playwright not installed. To use headless browser features, run these commands:"
            install_cmd1 = "pip install playwright"
            install_cmd2 = "playwright install chromium"
            logging.error(error_msg)
            logging.error(install_cmd1)
            logging.error(install_cmd2)
            console.print(f"[red]{error_msg}[/red]")
            console.print(f"[yellow]1. {install_cmd1}[/yellow]")
            console.print(f"[yellow]2. {install_cmd2}[/yellow]")
            return False
        except Exception as e:
            logging.error(f"Failed to initialize headless browser: {str(e)}")
            console.print(f"[red]Failed to initialize headless browser: {str(e)}[/red]")
            return False
    
    async def navigate(self, url: str, proxy: Optional[str] = None) -> Dict:
        """Navigate to a URL and analyze the page"""
        if not self.initialized:
            success = await self.initialize()
            if not success:
                return {"error": "Failed to initialize headless browser"}
        
        try:
            # Configure proxy if provided
            if proxy:
                await self.context.route("**", lambda route: route.continue_(proxy={"server": proxy}))
                
            # Navigate to the URL
            response = await self.page.goto(url, wait_until="networkidle", timeout=30000)
            status = response.status
            
            # Analyze the page
            has_login_form = await self.page.evaluate("""() => {
                const forms = Array.from(document.querySelectorAll('form'));
                return forms.some(form => {
                    const inputs = Array.from(form.querySelectorAll('input'));
                    return inputs.some(input => input.type === 'password');
                });
            }""")
            
            has_captcha = await self.page.evaluate("""() => {
                const html = document.documentElement.innerHTML.toLowerCase();
                return html.includes('captcha') || 
                       html.includes('recaptcha') || 
                       document.querySelector('iframe[src*="recaptcha"]') !== null ||
                       document.querySelector('iframe[src*="captcha"]') !== null;
            }""")
            
            title = await self.page.title()
            content = await self.page.content()
            
            # Take a screenshot
            screenshot = await self.page.screenshot(type="jpeg", quality=50)
            
            result = {
                "url": url,
                "status_code": status,
                "title": title,
                "has_login_form": has_login_form,
                "has_captcha": has_captcha,
                "content_length": len(content),
                "screenshot": screenshot
            }
            
            return result
            
        except Exception as e:
            logging.error(f"Error in headless navigation to {url}: {str(e)}")
            return {"error": str(e)}
    
    async def close(self):
        """Close the browser and clean up resources"""
        if self.browser:
            await self.browser.close()
        if hasattr(self, 'playwright') and self.playwright:
            await self.playwright.stop()
        self.initialized = False

class Menu:
    def __init__(self, config: Config, display: 'TerminalDisplay'):
        self.config = config
        self.display = display
        self.console = Console()
        
    def show_main_menu(self) -> str:
        """Show main menu and return selected option"""
        self.display.clear_screen()
        self.display.show_banner(self.config)
        
        menu = """
[cyan]Main Menu:[/]
1. Start Scan
2. Settings
3. View Results
4. Help
5. Exit

Select an option (1-5): """
        
        choice = self.console.input(menu)
        return choice
        
    def show_settings_menu(self) -> str:
        """Show settings menu and return selected option"""
        self.display.clear_screen()
        
        settings_panel = Panel(
            Group(
                Text("[cyan]Current Settings:[/]"),
                Text(f"Detection Mode: {self.config.DETECTION_MODE}"),
                Text(f"Max Concurrent Tasks: {self.config.MAX_CONCURRENT_TASKS}"),
                Text(f"Batch Size: {self.config.BATCH_SIZE}"),
                Text(f"Use Proxies: {self.config.USE_PROXIES}"),
                Text(f"Use Headless Browser: {self.config.USE_HEADLESS_BROWSER}"),
                Text(f"Custom Paths File: {self.config.CUSTOM_PATHS_FILE}"),
                Text(f"Max Paths: {self.config.MAX_PATHS}"),
                Text(f"Save Results: {self.config.SAVE_RESULTS}")
            ),
            title="Settings",
            border_style="cyan"
        )
        
        self.console.print(settings_panel)
        
        menu = """
[cyan]Settings Menu:[/]
1. Change Detection Mode
2. Configure Proxy Settings
3. Configure Browser Settings
4. Configure Paths Settings
5. Configure Output Settings
6. Save Settings
7. Load Settings
8. Reset to Default
9. Back to Main Menu

Select an option (1-9): """
        
        choice = self.console.input(menu)
        return choice
        
    def configure_detection_mode(self):
        """Configure detection mode settings"""
        self.display.clear_screen()
        
        modes = {
            "1": "simple",
            "2": "aggressive",
            "3": "stealth"
        }
        
        menu = """
[cyan]Select Detection Mode:[/]
1. Simple (Basic detection with minimal footprint)
2. Aggressive (Deep scanning with maximum efficacy)
3. Stealth (Evasive techniques to avoid detection)

Select mode (1-3): """
        
        choice = self.console.input(menu)
        if choice in modes:
            self.config.DETECTION_MODE = modes[choice]
            if choice == "2":  # Aggressive
                self.config.MAX_CONCURRENT_TASKS = 75
                self.config.BATCH_SIZE = 50
                self.config.CONNECTION_TIMEOUT = 5
                self.config.READ_TIMEOUT = 10
            elif choice == "3":  # Stealth
                self.config.MAX_CONCURRENT_TASKS = 10
                self.config.BATCH_SIZE = 5
                self.config.CONNECTION_TIMEOUT = 15
                self.config.READ_TIMEOUT = 30
                self.config.RETRY_DELAY = 3.0
            
            self.console.print(f"\n[green]Detection mode changed to {self.config.DETECTION_MODE}[/]")
        else:
            self.console.print("\n[red]Invalid choice[/]")
            
        self.console.input("\nPress Enter to continue...")
        
    def configure_proxy_settings(self):
        """Configure proxy settings"""
        self.display.clear_screen()
        
        menu = """
[cyan]Proxy Settings:[/]
1. Enable/Disable Proxies
2. Add Single Proxy
3. Load Proxy List from File
4. Back

Select an option (1-4): """
        
        choice = self.console.input(menu)
        
        if choice == "1":
            self.config.USE_PROXIES = not self.config.USE_PROXIES
            status = "enabled" if self.config.USE_PROXIES else "disabled"
            self.console.print(f"\n[green]Proxies {status}[/]")
        elif choice == "2":
            proxy = self.console.input("\nEnter proxy (format: http://host:port): ")
            if proxy:
                self.config.PROXIES.append(proxy)
                self.console.print(f"\n[green]Proxy {proxy} added[/]")
        elif choice == "3":
            filepath = self.console.input("\nEnter proxy list file path: ")
            if os.path.exists(filepath):
                with open(filepath) as f:
                    proxies = [line.strip() for line in f if line.strip()]
                    self.config.PROXIES.extend(proxies)
                self.console.print(f"\n[green]Loaded {len(proxies)} proxies[/]")
            else:
                self.console.print("\n[red]File not found[/]")
                
        self.console.input("\nPress Enter to continue...")

def setup_logging(config: Config):
    """Setup logging configuration"""
    # Create logs directory if it doesn't exist
    if not os.path.exists(config.LOGS_DIR):
        os.makedirs(config.LOGS_DIR)
        
    # Create a timestamped log filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(config.LOGS_DIR, f"scan_{timestamp}.log")
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Log initial information
    logging.info(f"Starting {config.TOOL_NAME} v{config.VERSION}")
    logging.info(f"Log file: {log_file}")

def setup_directories(config: Config):
    """Ensure all required directories exist"""
    directories = [
        config.LOGS_DIR,
        config.RESULTS_DIR
    ]
    
    try:
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                logging.info(f"Created directory: {directory}")
                
        # Check sub_links.json exists, if not create a basic one
        if not os.path.exists(config.CUSTOM_PATHS_FILE):
            logging.warning(f"Custom paths file {config.CUSTOM_PATHS_FILE} not found, creating a minimal version")
            with open(config.CUSTOM_PATHS_FILE, 'w') as f:
                json.dump([
                    "admin/", 
                    "admin.php", 
                    "administrator/", 
                    "login.php",
                    "wp-admin/",
                    "cp/",
                    "cpanel/",
                    "dashboard/"
                ], f, indent=4)
                
        return True
    except Exception as e:
        logging.error(f"Failed to create directories: {str(e)}")
        console.print(f"[red]Error creating directories: {str(e)}[/red]")
        console.print("[yellow]Make sure the application has write permissions in the current directory.[/yellow]")
        return False

def load_paths(config: Config) -> List[str]:
    """Load paths from the custom paths file"""
    paths = []
    
    try:
        # Check if file exists
        if not os.path.exists(config.CUSTOM_PATHS_FILE):
            logging.warning(f"Custom paths file not found: {config.CUSTOM_PATHS_FILE}")
            console.print(f"[yellow]Warning: Custom paths file not found: {config.CUSTOM_PATHS_FILE}[/yellow]")
            console.print("[yellow]Creating a new file with default paths...[/yellow]")
            
            # Create a basic paths file
            default_paths = [
                "admin/", "admin.php", "administrator/", "login.php",
                "wp-admin/", "cp/", "cpanel/", "dashboard/"
            ]
            
            with open(config.CUSTOM_PATHS_FILE, 'w') as f:
                json.dump(default_paths, f, indent=4)
                
            return default_paths
    
        # Load paths from file
        with open(config.CUSTOM_PATHS_FILE, 'r') as f:
            loaded_paths = json.load(f)
            
        if not isinstance(loaded_paths, list):
            logging.error(f"Invalid format in {config.CUSTOM_PATHS_FILE}. Expected a list.")
            console.print(f"[red]Error: Invalid format in {config.CUSTOM_PATHS_FILE}. Expected a list.[/red]")
            return []
            
        paths = loaded_paths
        
        # Apply maximum paths limit if configured
        if config.MAX_PATHS > 0 and len(paths) > config.MAX_PATHS:
            logging.info(f"Limiting paths to {config.MAX_PATHS} (from {len(paths)} available)")
            paths = paths[:config.MAX_PATHS]
            
        logging.info(f"Loaded {len(paths)} paths from {config.CUSTOM_PATHS_FILE}")
        return paths
        
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse {config.CUSTOM_PATHS_FILE}: {str(e)}")
        console.print(f"[red]Error: Failed to parse {config.CUSTOM_PATHS_FILE}: {str(e)}[/red]")
        console.print("[yellow]The file exists but contains invalid JSON. Using default paths instead.[/yellow]")
        return ["admin/", "admin.php", "administrator/", "login.php", "wp-admin/"]
        
    except Exception as e:
        logging.error(f"Error loading paths: {str(e)}")
        console.print(f"[red]Error loading paths: {str(e)}[/red]")
        return []

async def main():
    # Initialize components
    config = Config()
    display = TerminalDisplay()
    scanner = Scanner(config)
    exporter = ResultExporter(config)
    menu = Menu(config, display)
    
    # Setup logging and directories
    setup_logging(config)
    setup_directories(config)
    
    while True:
        choice = menu.show_main_menu()
        
        if choice == "1":  # Start Scan
            url = display.console.input("\nEnter target URL: ").strip()
            if not url:
                continue
                
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
                
            display.show_target_info(
                url, 
                scan_mode=config.DETECTION_MODE,
                proxies_enabled=config.USE_PROXIES,
                headless_enabled=config.USE_HEADLESS_BROWSER
            )
            
            # Load paths
            paths = load_paths(config)
            
            # Start scan
            start_time = time.time()
            retry_count = 0
            max_retries = 2  # Maximum number of scan retries
            
            while retry_count <= max_retries:
                results = await scanner.scan(url, paths, config.BATCH_SIZE)
                if results is not None:  # Scan completed successfully
                    break
                
                # If we reach here, scan failed
                retry_count += 1
                if retry_count <= max_retries:
                    logging.warning(f"Scan attempt {retry_count} failed, retrying...")
                    console.print(f"[yellow]Scan attempt failed, retrying ({retry_count}/{max_retries})...[/yellow]")
                    # Reset scanner session to ensure a fresh start
                    await scanner.cleanup()
                else:
                    logging.error("All scan attempts failed")
                    console.print("[red]All scan attempts failed. Please check your connection and try again.[/red]")
            
            scan_time = time.time() - start_time
            
            # Show and save results
            if results:
                display.show_results(results)
                
                # Show scan summary
                technologies = {}
                for result in results:
                    for tech in result.get("technologies", []):
                        technologies[tech] = technologies.get(tech, 0) + 1
                
                display.show_summary(
                    total_scanned=len(paths),
                    valid_found=len(results),
                    scan_time=scan_time,
                    technologies=technologies
                )
                
                if config.SAVE_RESULTS:
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    base_filename = os.path.join(config.RESULTS_DIR, f"scan_{timestamp}")
                    for format_type in config.EXPORT_FORMATS:
                        exporter.export_results(results, {
                            "target_url": url,
                            "scan_date": timestamp,
                            "scan_mode": config.DETECTION_MODE,
                            "total_paths": len(paths),
                            "valid_pages": len(results),
                            "scan_time": round(scan_time, 2)
                        }, format_type, base_filename)
                
                # Show scan completion and wait for user input
                display.show_scan_completion(results, scan_time, len(paths))
                display.console.input("[bold yellow]Press Enter to return to the main menu...[/bold yellow]")
            else:
                display.console.print("\n[yellow]No admin panels found for this URL.[/yellow]")
                display.console.print("\n[italic]This could be because:[/italic]")
                display.console.print(" • The site has no admin panel")
                display.console.print(" • The admin panel uses a custom path not in our database")
                display.console.print(" • The site has protection against scanning")
                display.console.print(" • There were connection issues during the scan\n")
                display.console.input("[bold yellow]Press Enter to return to the main menu...[/bold yellow]")
                
        elif choice == "2":  # Settings
            while True:
                settings_choice = menu.show_settings_menu()
                if settings_choice == "1":
                    menu.configure_detection_mode()
                elif settings_choice == "2":
                    menu.configure_proxy_settings()
                elif settings_choice == "6":
                    config.save_config()
                    display.console.print("\n[green]Settings saved[/]")
                elif settings_choice == "7":
                    config.load_config()
                    display.console.print("\n[green]Settings loaded[/]")
                elif settings_choice == "8":
                    config = Config()  # Reset to default
                    display.console.print("\n[green]Settings reset to default[/]")
                elif settings_choice == "9":
                    break
                    
                display.console.input("\nPress Enter to continue...")
                
        elif choice == "3":  # View Results
            # Show results directory contents
            if os.path.exists(config.RESULTS_DIR):
                files = os.listdir(config.RESULTS_DIR)
                if files:
                    display.show_results_list(files)
                else:
                    display.console.print("\n[yellow]No results found[/]")
            else:
                display.console.print("\n[yellow]Results directory not found[/]")
                
            display.console.input("\nPress Enter to continue...")
            
        elif choice == "4":  # Help
            display.show_help()
            display.console.input("\nPress Enter to continue...")
            
        elif choice == "5":  # Exit
            display.console.print("\n[cyan]Thanks for using Find The Admin Panel![/]")
            # Only cleanup before exiting
            await scanner.cleanup()
            break
            
        # Remove cleanup from here as it closes the session between menu actions
        # await scanner.cleanup()

if __name__ == "__main__":
    if platform.system().lower() == "windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        rprint("\n[bold yellow]Program terminated by user")
    except Exception as e:
        rprint(f"[bold red]Fatal error: {str(e)}")
