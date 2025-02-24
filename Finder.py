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
from typing import List, Optional, Dict, Set
from datetime import datetime
from bs4 import BeautifulSoup
from rich import print as rprint
from rich.console import Console
from rich.progress import Progress, TaskID, TextColumn, BarColumn, TimeRemainingColumn, SpinnerColumn
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
import ssl
import certifi
from colorama import init, Fore, Style
import cachetools
import signal
import random
import sys

init(autoreset=True)

@dataclass
class Config:
    VERSION: str = "4.0"
    DEVELOPER: str = "DV64"
    GITHUB: str = "https://github.com/dv64"
    TOOL_NAME: str = "Find The Admin Panel"
    RELEASE_DATE: str = "2025"
    CACHE_TTL: int = 3600
    CACHE_SIZE: int = 1000
    MAX_CONCURRENT_TASKS: int = 50
    CONNECTION_TIMEOUT: int = 10
    READ_TIMEOUT: int = 20
    BATCH_SIZE: int = 25
    VERIFY_SSL: bool = False
    MAX_RETRIES: int = 3
    RETRY_DELAY: float = 1.5
    USER_AGENTS: List[str] = field(default_factory=lambda: [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15"
    ])

class TerminalDisplay:
    def __init__(self):
        self.console = Console()
        
    def show_banner(self, config: Config):
        banner = """
    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
        """
        
        info_table = Table(show_header=False, box=None)
        info_table.add_row("[cyan]Tool Name    :", f"[white]{config.TOOL_NAME}")
        info_table.add_row("[cyan]Version      :", f"[white]{config.VERSION}")
        info_table.add_row("[cyan]Developer    :", f"[white]{config.DEVELOPER}")
        info_table.add_row("[cyan]GitHub       :", f"[white]{config.GITHUB}")
        info_table.add_row("[cyan]Release Date :", f"[white]{config.RELEASE_DATE}")
        
        self.console.print(Panel(banner, style="bold blue"))
        self.console.print(info_table)
        self.console.print("\n" + "="*70 + "\n")

    def show_target_info(self, url: str):
        target_table = Table(title="Target Information", show_header=True)
        target_table.add_column("Property", style="cyan")
        target_table.add_column("Value", style="white")
        
        parsed_url = urlparse(url)
        target_table.add_row("URL", url)
        target_table.add_row("Domain", parsed_url.netloc)
        target_table.add_row("Protocol", parsed_url.scheme)
        target_table.add_row("Scan Start Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        self.console.print(Panel(target_table, title="[bold cyan]Target Information", border_style="cyan"))
        self.console.print("\n")

    def show_result(self, result: Dict):
        # Determine color based on confidence
        confidence = result["confidence"]
        if confidence >= 0.7:
            confidence_color = "green"
        elif confidence >= 0.4:
            confidence_color = "yellow"
        else:
            confidence_color = "red"
            
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
        
        result_table = Table(show_header=False, box="rounded")
        result_table.add_column("Property", style="cyan")
        result_table.add_column("Value", style="white")
        
        result_table.add_row("URL", result["url"])
        result_table.add_row("Status Code", f"[{status_color}]{result['status_code']}[/]")
        result_table.add_row("Response Time", f"{result['response_time']:.2f}s")
        result_table.add_row("Server", result["server"])
        result_table.add_row("Title", result.get("title", "No Title"))
        result_table.add_row("Technologies", ", ".join(result["technologies"]))
        result_table.add_row("Forms Found", str(result["forms"]))
        result_table.add_row("Input Fields", str(result["inputs"]))
        result_table.add_row("Login Form", "[green]Yes[/]" if result["has_login_form"] else "[red]No[/]")
        result_table.add_row("Confidence", f"[{confidence_color}]{result['confidence']*100:.1f}%[/]")
        
        self.console.print(Panel(result_table, title=f"[bold cyan]Found Page: {result['url']}", border_style=confidence_color))
        self.console.print("\n")

    def show_summary(self, total_scanned: int, valid_found: int, scan_time: float):
        summary_table = Table(title="Scan Summary", show_header=False)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")
        
        # Calculate success rate
        success_rate = (valid_found / total_scanned) * 100 if total_scanned > 0 else 0
        if success_rate > 10:
            rate_color = "green"
        elif success_rate > 5:
            rate_color = "yellow"
        else:
            rate_color = "red"
        
        summary_table.add_row("Total URLs Scanned", str(total_scanned))
        summary_table.add_row("Valid Pages Found", f"[{rate_color}]{valid_found}[/]")
        summary_table.add_row("Success Rate", f"[{rate_color}]{success_rate:.2f}%[/]")
        summary_table.add_row("Total Scan Time", f"{scan_time:.2f} seconds")
        summary_table.add_row("Average Time per URL", f"{(scan_time / total_scanned):.4f} seconds" if total_scanned > 0 else "N/A")
        summary_table.add_row("Scan End Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        self.console.print(Panel(summary_table, title="[bold cyan]Scan Summary", border_style="cyan"))
    
    def show_help(self):
        help_text = """
        [bold cyan]Command Line Arguments:[/]
        
        -u, --url      Target URL to scan
        -p, --pathfile Custom path file (JSON format)
        -o, --output   Output file for results
        -j, --json     Save results in JSON format
        -q, --quiet    Quiet mode (less output)
        
        [bold cyan]Examples:[/]
        
        python Find.py -u https://example.com -j
        python Find.py -u https://example.com -p custom_paths.json -o results.txt
        python Find.py -u https://example.com -j -q
        """
        self.console.print(Panel(help_text, title="[bold cyan]Help Information", border_style="cyan"))

class Scanner:
    def __init__(self, config: Config):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.discovered_urls: Set[str] = set()
        self.scan_start_time: float = 0
        self.found_urls: List[Dict] = []
        self._setup_logging()

    def _setup_logging(self):
        logging.basicConfig(
            filename=f'scanner_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

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
        return {
            "User-Agent": random.choice(self.config.USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

    async def analyze_response(self, response: aiohttp.ClientResponse, url: str) -> Dict:
        try:
            text = await response.text()
            soup = BeautifulSoup(text, 'html.parser')
            
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
            
            return {
                "status_code": response.status,
                "content_type": response.headers.get("Content-Type", ""),
                "server": response.headers.get("Server", "Unknown"),
                "title": soup.title.string if soup.title else "No Title",
                "forms": len(soup.find_all("form")),
                "inputs": len(soup.find_all("input")),
                "has_login_form": bool(soup.find("form", {"method": "post"})),
                "technologies": self._detect_technologies(text, response.headers),
                "meta_tags": meta_tags,
                "links_count": len(links),
                "content_length": len(text),
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
            }

    def _detect_technologies(self, html: str, headers: Dict) -> List[str]:
        technologies = []
        html_lower = html.lower()
        
        tech_signatures = {
            "wordpress": ["wp-content", "wp-includes"],
            "drupal": ["drupal", "sites/all"],
            "joomla": ["joomla", "com_content"],
            "laravel": ["laravel", "csrf-token"],
            "django": ["csrfmiddlewaretoken", "django"],
            "react": ["react", "react-dom"],
            "vue": ["vue.js", "vuejs"],
            "bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
            "jquery": ["jquery.min.js", "jquery-"],
            "php": ["php", ".php"],
            "asp.net": ["__viewstate", "asp.net"],
            "nodejs": ["node_modules", "express"],
            "angularjs": ["ng-", "angular"],
            "ruby": ["rails", "ruby"],
            "java": ["java", "jsessionid"]
        }
        
        for tech, signatures in tech_signatures.items():
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
        if headers.get("X-XSS-Protection"):
            technologies.append("XSS-Protection")
        if headers.get("Content-Security-Policy"):
            technologies.append("CSP")
        if headers.get("X-Frame-Options"):
            technologies.append("X-Frame-Options")
            
        return list(set(technologies))

    async def scan_url(self, base_url: str, path: str, progress=None, task_id=None) -> Optional[Dict]:
        full_url = urljoin(base_url, path.lstrip("/"))
        
        for attempt in range(self.config.MAX_RETRIES):
            try:
                start_time = time.time()
                async with self.session.get(
                    full_url,
                    allow_redirects=True,
                    headers=self._get_headers(),
                    ssl=self.config.VERIFY_SSL
                ) as response:
                    response_time = time.time() - start_time
                    
                    if 200 <= response.status < 500:
                        analysis = await self.analyze_response(response, full_url)
                        confidence = self._calculate_confidence(analysis)
                        
                        result = {
                            "url": full_url,
                            "path": path,
                            "is_valid": True,
                            "status_code": response.status,
                            "response_time": response_time,
                            "confidence": confidence,
                            **analysis
                        }
                        
                        self.found_urls.append(result)
                        return result
                    elif response.status == 404:
                        # Don't retry for 404
                        break
                        
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt == self.config.MAX_RETRIES - 1:
                    logging.error(f"Error scanning {full_url}: {str(e)}")
                await asyncio.sleep(self.config.RETRY_DELAY * (attempt + 1))
            except Exception as e:
                logging.error(f"Unexpected error scanning {full_url}: {str(e)}")
                break
        
        if progress and task_id:
            progress.update(task_id, advance=1)
                
        return None

    def _calculate_confidence(self, analysis: Dict) -> float:
        confidence = 0.0
        
        # Confidence based on response analysis
        if analysis["has_login_form"]:
            confidence += 0.4
        if analysis["forms"] > 0:
            confidence += 0.2
        if analysis["inputs"] > 2:
            confidence += 0.2
            
        # Confidence based on technologies
        if analysis["technologies"]:
            confidence += min(0.2, len(analysis["technologies"]) * 0.05)
            
        # Confidence based on links count (admin pages often have many links)
        if analysis["links_count"] > 10:
            confidence += 0.1
            
        # Confidence based on title
        title = analysis.get("title", "").lower()
        admin_terms = ["admin", "administrator", "dashboard", "control", "panel", "login"]
        if any(term in title for term in admin_terms):
            confidence += 0.2
            
        return min(confidence, 1.0)

    async def _process_batch(self, url: str, batch: List[str], progress=None, task_id=None) -> List[Dict]:
        tasks = []
        for path in batch:
            task = self.scan_url(url, path, progress, task_id)
            tasks.append(task)
            
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        results = []
        
        for result in batch_results:
            if isinstance(result, dict) and result.get("is_valid"):
                results.append(result)
                
        if progress and task_id:
            progress.update(task_id, advance=len(batch))
                
        return results

    async def scan(self, url: str, paths: List[str], concurrency: int = None) -> List[Dict]:
        if not self.session:
            await self.create_session()
            
        self.found_urls = []
        self.scan_start_time = time.time()
        
        batch_size = concurrency if concurrency else self.config.BATCH_SIZE
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeRemainingColumn()
        ) as progress:
            scan_task = progress.add_task(
                "[cyan]Scanning...", 
                total=len(paths)
            )
            
            for i in range(0, len(paths), batch_size):
                batch = paths[i:i + batch_size]
                await self._process_batch(url, batch, progress, scan_task)
                await asyncio.sleep(0.1)  # Small delay to prevent CPU hogging
                
        return sorted(
            self.found_urls,
            key=lambda x: (x.get("confidence", 0), x.get("status_code", 0) == 200),
            reverse=True
        )

    async def cleanup(self):
        if self.session:
            await self.session.close()

async def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Find The Admin Panel - Version 4.0', add_help=False)
    parser.add_argument('-u', '--url', help='Target URL to scan')
    parser.add_argument('-p', '--pathfile', help='Custom path file (JSON format)')
    parser.add_argument('-o', '--output', help='Output file for results (default: scan_report_YYYYMMDD_HHMMSS.txt)')
    parser.add_argument('-j', '--json', action='store_true', help='Save results in JSON format')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (less output)')
    parser.add_argument('-c', '--concurrency', type=int, help='Number of concurrent requests (default: 25)')
    parser.add_argument('-h', '--help', action='store_true', help='Show help information')
    args = parser.parse_args()
    
    config = Config()
    scanner = Scanner(config)
    display = TerminalDisplay()
    
    # Show help if requested
    if args.help:
        display.show_banner(config)
        display.show_help()
        return
    
    while True:
        try:
            display.show_banner(config)
            
            # Get URL from argument or prompt
            url = args.url if args.url else input("Enter target URL: ").strip()
            if not url:
                return
                
            if not url.startswith(('http://', 'https://')):
                url = f'http://{url}'
                
            display.show_target_info(url)
            
            # Default paths to scan
            default_paths = [
                "admin", "administrator", "admin1", "admin2", "admin3",
                "admin/login", "admin/login.php", "admin/cp.php", "admin/control",
                "administrator/index.php", "admin.php", "admincp", "wp-admin",
                "admin/controlpanel.php", "admin/dashboard", "admin/home",
                "admin-login", "panel-admin", "instadmin", "member", "members",
                "user", "users", "cp", "controlpanel", "admincontrol",
                "admin/adminLogin", "admin/admin-login", "adminLogin", "dashboard",
                "moderator", "webadmin", "backoffice", "manager", "panel",
                "login", "login.php", "portal", "portal.php", "dashboard.php",
                "wp-login.php", "wp-admin.php", "admin/index.php", "admin/home.php",
                "administrator/login.php", "administrator/admin.php",
                "phpmyadmin", "phpMyAdmin", "admin/phpmyadmin",
                "administrator/dashboard", "administrator/dashboard.php",
                "admin/dashboard.html", "admin/login.html",
                "moderator/login.php", "moderator/admin.php",
                "moderator.php", "moderator.html",
                "moderator/login.html", "moderator/admin.html",
                "controlpanel.php", "controlpanel.html",
                "administrator.php", "administrator.html",
                "admin_area", "admin_area/login", "admin_area/index",
                "siteadmin", "siteadmin/login", "siteadmin/index",
                "siteadmin/login.php", "admin/account.php",
                "admin/index.php", "admin/login.php", "admin/admin.php",
                "admin/account.php", "admin_area/admin.php",
                "admin_area/login.php", "siteadmin/login.html",
                "siteadmin/index.html", "siteadmin/login.php",
                "admin/admin_login.php", "admin_login.php",
                "panel-administracion", "adminLogin", "admin/adminLogin",
                "home.php", "admin.php", "admin/home",
                "admin/controlpanel", "admin/admin-login",
                "admin-login", "admin/cp", "cp",
                "administrator/account.php", "administrator.php",
                "nsw/admin/login.php", "webadmin/login.php",
                "admin/admin_login.php", "admin_login.php",
                "administrator/account.php", "administrator.php",
                "admin_area/admin.php", "pages/admin/admin-login.php",
                "admin/admin-login.php", "admin-login.php",
                "bb-admin/index.php", "bb-admin/login.php",
                "bb-admin/admin.php", "admin/home.php",
                "admin_area/login.html", "admin/index.html",
                "admin/login.html", "admin/admin.html"
            ]
            
            # Check if custom path file is provided
            custom_path_file = args.pathfile if args.pathfile else "sub_links.json"
            
            # Check if sub_links.json exists and load paths from it
            paths = default_paths.copy()
            try:
                if os.path.exists(custom_path_file):
                    if not args.quiet:
                        rprint(f"[bold cyan]Found {custom_path_file}, loading additional paths...[/]")
                    with open(custom_path_file, "r") as f:
                        json_paths = json.load(f)
                        # Add paths from JSON file that aren't already in the default list
                        new_paths = [p for p in json_paths if p not in paths]
                        paths.extend(new_paths)
                        if not args.quiet:
                            rprint(f"[bold green]Added {len(new_paths)} additional paths from {custom_path_file}[/]")
                elif custom_path_file != "sub_links.json" and args.pathfile:
                    # User specified a custom path file that doesn't exist
                    rprint(f"[bold red]Custom path file '{custom_path_file}' not found![/]")
                    return
                else:
                    if not args.quiet:
                        rprint("[bold yellow]sub_links.json not found, using default paths[/]")
            except Exception as e:
                logging.error(f"Error loading {custom_path_file}: {str(e)}")
                rprint(f"[bold red]Error loading {custom_path_file}: {str(e)}[/]")
                rprint("[bold yellow]Using default paths instead[/]")
            
            # Set concurrency level
            concurrency = args.concurrency if args.concurrency else config.BATCH_SIZE
            
            if not args.quiet:
                rprint(f"[bold cyan]Starting scan with {len(paths)} paths and {concurrency} concurrent requests...[/]")
            start_time = time.time()
            results = await scanner.scan(url, paths, concurrency)
            scan_time = time.time() - start_time
            
            if results:
                if not args.quiet:
                    rprint("\n[bold green]Valid pages found:[/]\n")
                    for result in results:
                        display.show_result(result)
                
                # Determine output file name
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                if args.output:
                    base_filename = args.output
                    if args.json and not base_filename.endswith('.json'):
                        base_filename = os.path.splitext(base_filename)[0]
                else:
                    base_filename = f"scan_report_{timestamp}"
                
                # Save results in specified format
                if args.json:
                    json_file = f"{base_filename}.json"
                    with open(json_file, "w", encoding="utf-8") as f:
                        json_data = {
                            "scan_info": {
                                "target_url": url,
                                "scan_date": timestamp,
                                "total_paths": len(paths),
                                "valid_pages": len(results),
                                "scan_time": round(scan_time, 2)
                            },
                            "results": results
                        }
                        json.dump(json_data, f, indent=4)
                    if not args.quiet:
                        rprint(f"\n[bold blue]JSON results saved to: {json_file}")
                
                # Always save text report unless quiet mode
                if not args.quiet or not args.json:
                    report_file = f"{base_filename}.txt"
                    # Generate and save detailed report
                    with open(report_file, "w", encoding="utf-8") as f:
                        f.write(f"Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Target URL: {url}\n")
                        f.write("=" * 50 + "\n\n")
                        
                        for result in results:
                            f.write(f"URL: {result['url']}\n")
                            f.write(f"Status Code: {result['status_code']}\n")
                            f.write(f"Response Time: {result['response_time']:.2f}s\n")
                            f.write(f"Server: {result['server']}\n")
                            f.write(f"Technologies: {', '.join(result['technologies'])}\n")
                            f.write(f"Forms Found: {result['forms']}\n")
                            f.write(f"Input Fields: {result['inputs']}\n")
                            f.write(f"Login Form: {'Yes' if result['has_login_form'] else 'No'}\n")
                            f.write(f"Confidence: {result['confidence']*100:.1f}%\n")
                            f.write("\n" + "=" * 50 + "\n")
                    
                    if not args.quiet:
                        rprint(f"\n[bold blue]Full report saved to: {report_file}")
                
                if not args.quiet:
                    display.show_summary(len(paths), len(results), scan_time)
            else:
                if not args.quiet:
                    rprint("[bold yellow]No valid pages found.")
                    display.show_summary(len(paths), 0, scan_time)
            
            # If URL was provided via command line, exit after one scan
            if args.url:
                break
                
        except KeyboardInterrupt:
            rprint("\n[bold yellow]Scan cancelled by user")
            break
        except Exception as e:
            logging.error(f"Error: {str(e)}")
            rprint(f"[bold red]Error: {str(e)}")
        finally:
            await scanner.cleanup()
        
        if not args.url:
            repeat = input("\nDo you want to scan another URL? (yes/no): ").strip().lower()
            if repeat != 'yes':
                break
        else:
            break

if __name__ == "__main__":
    if platform.system().lower() == "windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        rprint("\n[bold yellow]Program terminated by user")
    except Exception as e:
        rprint(f"[bold red]Fatal error: {str(e)}")
