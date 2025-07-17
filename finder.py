import os
import sys
import asyncio
import argparse
from datetime import datetime
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scripts.config import Config
from scripts.ui import TerminalDisplay
from scripts.scanner import Scanner
from scripts.exporter import ResultExporter
from scripts.menu import start_menu
from scripts.utils import setup_signal_handler, validate_url, count_lines_in_file
from scripts.logging import get_logger
from scripts.scan_helper import auto_update_wordlist

adv_logger = get_logger('logs')


async def scan_target(config, target_url, wordlist_path=None, export_format="", interactive=False):
    display = TerminalDisplay()
    
    if not wordlist_path:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(base_dir, config.DEFAULT_WORDLIST)
    
    is_valid, target_url = validate_url(target_url)
    if not is_valid:
        adv_logger.log_error(f"Invalid URL format: {target_url}")
        if interactive:
            display.show_error(f"Invalid URL format: {target_url}")
            return [], {}
        else:
            print(f"Error: Invalid URL format: {target_url}")
            sys.exit(1)
    
    if not os.path.exists(wordlist_path):
        adv_logger.log_error(f"Wordlist file not found: {wordlist_path}")
        if interactive:
            display.show_error(f"Wordlist file not found: {wordlist_path}")
            return [], {}
        else:
            print(f"Error: Wordlist file not found: {wordlist_path}")
            sys.exit(1)
    
    scanner = await Scanner.create(config)
    
    setup_signal_handler(scanner)
    
    try:
        paths = []
        if wordlist_path.endswith('.json'):
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        paths = data
                    elif isinstance(data, dict) and 'paths' in data:
                        paths = data['paths']
                    else:
                        adv_logger.log_error(f"Invalid JSON format in wordlist: {wordlist_path}")
                        paths = []
            except Exception as e:
                adv_logger.log_error(f"Error reading JSON wordlist: {str(e)}")
                if interactive:
                    display.show_error(f"Error reading JSON wordlist: {str(e)}")
                    return [], {}
                else:
                    print(f"Error: {str(e)}")
                    sys.exit(1)
        else:
            try:
                with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except Exception as e:
                adv_logger.log_error(f"Error reading wordlist file: {str(e)}")
                if interactive:
                    display.show_error(f"Error reading wordlist file: {str(e)}")
                    return [], {}
                else:
                    print(f"Error: {str(e)}")
                    sys.exit(1)
        
        paths = [p for p in paths if p and isinstance(p, str)]
        
        mode_config = config.get_current_mode_config()
        if config.DETECTION_MODE == "simple" and len(paths) > 1000:
            original_count = len(paths)
            paths = paths[:1000]
            adv_logger.log_info(f"Simple mode: Limited paths from {original_count} to {len(paths)}")
        elif config.DETECTION_MODE == "stealth" and len(paths) > 500:
            original_count = len(paths)
            admin_keywords = ['admin', 'administrator', 'dashboard', 'panel', 'control', 'login', 'cp']
            prioritized_paths = [p for p in paths if any(keyword in p.lower() for keyword in admin_keywords)]
            
            random_paths = list(set(paths) - set(prioritized_paths))
            import random
            if random_paths:
                random.shuffle(random_paths)
                selected_random = random_paths[:200]
            else:
                selected_random = []
                
            paths = prioritized_paths[:300] + selected_random
            adv_logger.log_info(f"Stealth mode: Selected {len(paths)} optimized paths from {original_count}")
        
        scan_mode = "custom" if wordlist_path != os.path.join(base_dir, config.DEFAULT_WORDLIST) else "default"
        adv_logger.log_scan_start(target_url, scan_mode, len(paths))
        
        if interactive:
            display.clear_screen()
            display.show_banner(config)
            display.show_target_info(target_url, scan_mode, wordlist_path)
        else:
            print(f"Starting scan on {target_url}")
            print(f"Using wordlist: {wordlist_path} ({len(paths)} paths)")
            print(f"Mode: {config.DETECTION_MODE} - {mode_config.get('DESCRIPTION', '')}")
        
        start_time = datetime.now()
        results = await scanner.scan(target_url, paths)
        scan_time = (datetime.now() - start_time).total_seconds()
        
        scan_info = scanner.get_scan_info()
        scan_info["scan_time"] = scan_time
        scan_info["target_url"] = target_url
        scan_info["scan_mode"] = scan_mode
        scan_info["detection_mode"] = config.DETECTION_MODE
        scan_info["total_paths"] = len(paths)
        
        adv_logger.log_scan_complete(
            target_url, 
            len(paths), 
            sum(1 for r in results if r.get("found", False)), 
            scan_time
        )
        
        if interactive:
            display.show_scan_completion(results, scan_time, len(paths))
            display.show_results(results)
            display.show_summary(len(paths), sum(1 for r in results if r.get("found", False)), scan_time)
        else:
            found_count = sum(1 for r in results if r.get("found", False))
            print(f"\nScan completed in {scan_time:.2f} seconds")
            print(f"Checked {len(paths)} paths")
            print(f"Found {found_count} potential admin panels\n")
            
            if found_count > 0:
                print("\nPotential admin panels found:")
                for r in results:
                    if r.get("found", False):
                        print(f"  - {r.get('url')} (Confidence: {r.get('confidence', 0):.2f}, Status: {r.get('status_code', 0)})")
        
        if config.SAVE_RESULTS:
            exporter = ResultExporter(config)
            if interactive:
                display.show_progress("Exporting results...")
            else:
                print("Exporting results...")
            
            export_format = export_format or config.EXPORT_FORMATS[0] or "txt"
            export_status = exporter.export_results(results, scan_info, export_format)
            
            if interactive:
                display.show_success("Results exported successfully")
        
        return results, scan_info
        
    except Exception as e:
        adv_logger.log_error(f"Error during scan: {str(e)}")
        if interactive:
            display.show_error(f"Error during scan: {str(e)}")
        else:
            print(f"Error: {str(e)}")
        return [], {}
    finally:
        await scanner.close()


async def update_wordlists(config, source_url=None, interactive=False):
    display = TerminalDisplay()
    
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        default_wordlist_path = os.path.join(base_dir, config.DEFAULT_WORDLIST)
        
        if interactive:
            display.clear_screen()
            display.show_banner(config)
            display.show_progress(f"Updating wordlists...")
        else:
            print(f"Updating wordlists...")
            
        success, message, stats = auto_update_wordlist(default_wordlist_path, source_url)
        
        if success:
            if interactive:
                display.show_success(message)
                display.show_info(f"Original paths: {stats['original_count']}")
                display.show_info(f"New paths: {stats['final_count']}")
                display.show_info(f"Added: {stats['added_count']} (+{stats['percent_increase']}%)")
            else:
                print(f"Success: {message}")
                print(f"Original paths: {stats['original_count']}")
                print(f"New paths: {stats['final_count']}")
                print(f"Added: {stats['added_count']} (+{stats['percent_increase']}%)")
            return True
        else:
            if interactive:
                display.show_error(message)
            else:
                print(f"Error: {message}")
            return False
    
    except Exception as e:
        error_msg = f"Error updating wordlists: {str(e)}"
        adv_logger.log_error(error_msg)
        
        if interactive:
            display.show_error(error_msg)
        else:
            print(f"Error: {error_msg}")
        
        return False


async def main():
    try:
        config = Config()
        
        parser = argparse.ArgumentParser(description="Find The Admin Panel - A tool for identifying admin panels")
        parser.add_argument("-u", "--url", help="Target URL to scan")
        parser.add_argument("-w", "--wordlist", help="Path to wordlist file")
        parser.add_argument("-e", "--export", help="Export format (json, html, csv, txt)")
        parser.add_argument("-i", "--interactive", action="store_true", help="Run in interactive mode")
        parser.add_argument("-v", "--version", action="store_true", help="Show version and exit")
        parser.add_argument("--update-wordlist", action="store_true", help="Update wordlists with latest paths")
        parser.add_argument("--source", help="Source URL for wordlist updates")
        parser.add_argument("--http3", action="store_true", help="Enable HTTP/3 protocol support")
        parser.add_argument("--machine-learning", action="store_true", help="Enable machine learning-based detection")
        parser.add_argument("--fuzzing", action="store_true", help="Enable path fuzzing capabilities")
        parser.add_argument("--concurrency", type=int, help="Set maximum concurrent requests")
        parser.add_argument("--detection-mode", choices=["simple", "stealth", "aggressive"], 
                           help="Set the detection mode (simple, stealth, aggressive)")
        
        args = parser.parse_args()
        
        if args.version:
            print(f"Find The Admin Panel v{config.VERSION}")
            print(f"Developed by: {config.DEVELOPER}")
            print(f"GitHub: {config.GITHUB}")
            return
            
        if args.update_wordlist:
            await update_wordlists(config, args.source, args.interactive)
            if not args.url:  
                return
        
        if args.detection_mode and args.detection_mode in config.DETECTION_MODES:
            config.DETECTION_MODE = args.detection_mode
            adv_logger.log_info(f"Detection mode set to: {args.detection_mode}")
            config._setup_detection_modes()
        
        if hasattr(config, 'USE_HTTP3') and args.http3:
            config.USE_HTTP3 = True
            adv_logger.log_info("HTTP/3 support enabled")
            
        if hasattr(config, 'USE_ML_DETECTION') and args.machine_learning:
            config.USE_ML_DETECTION = True
            adv_logger.log_info("Machine learning-based detection enabled")
            
        if hasattr(config, 'USE_PATH_FUZZING') and args.fuzzing:
            config.USE_PATH_FUZZING = True
            adv_logger.log_info("Path fuzzing capabilities enabled")
            
        if args.concurrency and args.concurrency > 0:
            config.MAX_CONCURRENT_TASKS = args.concurrency
            adv_logger.log_info(f"Concurrency set to {args.concurrency}")
        
        if args.interactive or not args.url:
            await start_menu(config)
        else:
            await scan_target(config, args.url, args.wordlist, args.export, False)
            
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        adv_logger.log_warning("Scan interrupted by user (Ctrl+C)")
    except Exception as e:
        print(f"Error: {str(e)}")
        adv_logger.log_error(f"Unhandled error: {str(e)}")


if __name__ == "__main__":
    asyncio.run(main())
