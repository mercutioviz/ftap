import os
import json
import csv
import html
from datetime import datetime
from typing import List, Dict
from urllib.parse import urlparse

from scripts.logging import get_logger

adv_logger = get_logger('logs')

class ResultExporter:
    
    def __init__(self, config):
        self.config = config
        self.results_dir = config.RESULTS_DIR
        self.supported_formats = ["json", "html", "csv", "txt"]
        if not hasattr(config, 'EXPORT_FORMATS') or not config.EXPORT_FORMATS:
            self.config.EXPORT_FORMATS = ["json", "html"]
            adv_logger.log_info("No export formats configured, using defaults: json, html")
            
        os.makedirs(self.results_dir, exist_ok=True)
        adv_logger.log_info(f"Ensuring results directory exists: {self.results_dir}")
    
    def _get_timestamp(self) -> str:
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def _get_result_filename(self, base_filename: str = "", format_type: str = "json") -> str:
        timestamp = self._get_timestamp()
        if base_filename:
            safe_basename = os.path.basename(base_filename)
            return f"{self.results_dir}/{safe_basename}_{timestamp}.{format_type}"
        else:
            return f"{self.results_dir}/results_{timestamp}.{format_type}"
    
    def _ensure_result_has_required_fields(self, result: Dict) -> Dict:
        required_fields = {
            "url": "Unknown",
            "status_code": 0,
            "title": "Unknown",
            "confidence": 0.0,
            "found": False,
            "has_login_form": False,
            "technologies": [],
            "headers": {},
            "server": "Unknown",
            "forms": [],
            "inputs": [],
            "content_length": 0
        }
        
        safe_result = result.copy()
        
        if "headers" in safe_result and "Server" in safe_result["headers"]:
            safe_result["server"] = safe_result["headers"]["Server"]
        
        for field, default_value in required_fields.items():
            if field not in safe_result or safe_result[field] is None:
                safe_result[field] = default_value
                
        return safe_result
    
    def _export_json(self, results: List[Dict], scan_info: Dict, filename: str) -> bool:
        try:
            safe_results = [self._ensure_result_has_required_fields(r) for r in results]
            
            export_data = {
                "scan_info": scan_info,
                "results": safe_results,
                "total_count": len(safe_results),
                "found_count": sum(1 for r in safe_results if r.get("found", False)),
                "export_time": datetime.now().isoformat()
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=4, ensure_ascii=False)
            adv_logger.log_info(f"Exported {len(results)} results to JSON: {filename}")
            return True
        except Exception as e:
            adv_logger.log_error(f"Failed to export to JSON: {str(e)}")
            return False
    
    def _export_html(self, results: List[Dict], scan_info: Dict, filename: str) -> bool:
        try:
            safe_results = [self._ensure_result_has_required_fields(r) for r in results]
            
            url = scan_info.get("target_url", "Unknown")
            mode = scan_info.get("scan_mode", "Unknown")
            duration = scan_info.get("scan_time", 0)
            total_paths = scan_info.get("total_paths", 0)
            found_count = sum(1 for r in safe_results if r.get("found", False))
            
            html_content = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Admin Panel Finder Results - {url}</title>
                <style>
                    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                    .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                    .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                    .summary {{ background-color: #f8f9fa; padding: 15px; margin: 20px 0; border-radius: 5px; border-left: 4px solid #2c3e50; }}
                    h1, h2, h3 {{ margin-top: 0; }}
                    table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
                    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                    th {{ background-color: #2c3e50; color: white; position: sticky; top: 0; }}
                    tr:hover {{ background-color: #f5f5f5; }}
                    .success {{ color: green; }}
                    .warning {{ color: orange; }}
                    .error {{ color: red; }}
                    .badge {{ display: inline-block; padding: 3px 7px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-right: 5px; }}
                    .badge-blue {{ background-color: #3498db; color: white; }}
                    .badge-green {{ background-color: #2ecc71; color: white; }}
                    .badge-red {{ background-color: #e74c3c; color: white; }}
                    .badge-orange {{ background-color: #f39c12; color: white; }}
                    .tech-list {{ margin: 0; padding: 0; list-style: none; display: flex; flex-wrap: wrap; }}
                    .tech-list li {{ margin-right: 8px; margin-bottom: 5px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Admin Panel Finder Results</h1>
                        <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    </div>
                    
                    <div class="summary">
                        <h2>Scan Summary</h2>
                        <p><strong>Target URL:</strong> {url}</p>
                        <p><strong>Scan Mode:</strong> {mode}</p>
                        <p><strong>Duration:</strong> {duration:.2f} seconds</p>
                        <p><strong>Found:</strong> {found_count} potential admin panels</p>
                        <p><strong>Total Paths Checked:</strong> {total_paths}</p>
                        <p><strong>Success Rate:</strong> {(found_count/total_paths*100) if total_paths > 0 else 0:.2f}%</p>
                    </div>
                    
                    <h2>Results</h2>
            """
            
            if not safe_results:
                html_content += "<p>No potential admin panels found.</p>"
            else:
                html_content += """
                    <table>
                        <thead>
                            <tr>
                                <th>URL</th>
                                <th>Status</th>
                                <th>Title</th>
                                <th>Confidence</th>
                                <th>Features</th>
                                <th>Technologies</th>
                            </tr>
                        </thead>
                        <tbody>
                """
                
                for result in safe_results:
                    confidence = result.get("confidence", 0) * 100
                    confidence_class = "success" if confidence > 70 else "warning" if confidence > 40 else "error"
                    
                    features = []
                    if result.get("has_login_form", False):
                        features.append('<span class="badge badge-green">Login Form</span>')
                    if "forms" in result and len(result["forms"]) > 0:
                        features.append(f'<span class="badge badge-blue">{len(result["forms"])} Forms</span>')
                    if result.get("status_code", 0) == 401 or result.get("status_code", 0) == 403:
                        features.append('<span class="badge badge-orange">Authentication Required</span>')
                        
                    technologies = ""
                    if result.get("technologies", []):
                        technologies = '<ul class="tech-list">' + ''.join([f'<li><span class="badge badge-blue">{tech}</span></li>' for tech in result.get("technologies", [])]) + '</ul>'
                    
                    html_content += f"""
                        <tr>
                            <td><a href="{result.get('url', '#')}" target="_blank">{result.get('url', 'Unknown')}</a></td>
                            <td>{result.get('status_code', 'Unknown')}</td>
                            <td>{html.escape(result.get('title', 'Unknown'))}</td>
                            <td class="{confidence_class}">{confidence:.1f}%</td>
                            <td>{"".join(features)}</td>
                            <td>{technologies}</td>
                        </tr>
                    """
                
                html_content += """
                        </tbody>
                    </table>
                """
            
            html_content += """
                </div>
                <script>
                    document.addEventListener("DOMContentLoaded", function() {
                        // Add any JavaScript enhancements here
                    });
                </script>
            </body>
            </html>
            """
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            adv_logger.log_info(f"Exported {len(results)} results to HTML: {filename}")
            return True
            
        except Exception as e:
            adv_logger.log_error(f"Failed to export to HTML: {str(e)}")
            return False
    
    def _export_csv(self, results: List[Dict], scan_info: Dict, filename: str) -> bool:
        try:
            safe_results = [self._ensure_result_has_required_fields(r) for r in results]
            
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                writer.writerow([
                    "URL", "Status", "Title", "Confidence", "Has Login Form", 
                    "Technologies", "Server", "Content Length", "Form Count"
                ])
                
                for result in safe_results:
                    writer.writerow([
                        result.get("url", "Unknown"),
                        result.get("status_code", "Unknown"),
                        result.get("title", "Unknown"),
                        f"{result.get('confidence', 0) * 100:.1f}%",
                        "Yes" if result.get("has_login_form", False) else "No",
                        ", ".join(result.get("technologies", [])),
                        result.get("server", "Unknown"),
                        result.get("content_length", 0),
                        len(result.get("forms", []))
                    ])
            
            adv_logger.log_info(f"Exported {len(results)} results to CSV: {filename}")
            return True
            
        except Exception as e:
            adv_logger.log_error(f"Failed to export to CSV: {str(e)}")
            return False
    
    def _export_txt(self, results: List[Dict], scan_info: Dict, filename: str) -> bool:
        try:
            safe_results = [self._ensure_result_has_required_fields(r) for r in results]
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("===== Admin Panel Finder Results =====\n")
                f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write(f"Target URL: {scan_info.get('target_url', 'Unknown')}\n")
                f.write(f"Scan Mode: {scan_info.get('scan_mode', 'Unknown')}\n")
                f.write(f"Total Paths Checked: {scan_info.get('total_paths', 0)}\n")
                f.write(f"Scan Duration: {scan_info.get('scan_time', 0):.2f} seconds\n\n")
                
                f.write(f"Found {len(safe_results)} potential admin panels\n\n")
                
                for i, result in enumerate(safe_results, 1):
                    confidence = result.get("confidence", 0) * 100
                    f.write(f"[{i}] {result.get('url', 'Unknown')}\n")
                    f.write(f"    Status Code: {result.get('status_code', 'Unknown')}\n")
                    f.write(f"    Title: {result.get('title', 'Unknown')}\n")
                    f.write(f"    Confidence: {confidence:.1f}%\n")
                    f.write(f"    Server: {result.get('server', 'Unknown')}\n")
                    
                    f.write(f"    Has Login Form: {'Yes' if result.get('has_login_form', False) else 'No'}\n")
                    
                    if result.get("technologies", []):
                        f.write(f"    Technologies: {', '.join(result.get('technologies', []))}\n")
                    
                    f.write("\n")
            
            adv_logger.log_info(f"Exported {len(results)} results to TXT: {filename}")
            return True
            
        except Exception as e:
            adv_logger.log_error(f"Failed to export to TXT: {str(e)}")
            return False
    
    def export_results(self, results: List[Dict], scan_info: Dict, format_type: str = "", base_filename: str = "") -> Dict[str, bool]:
        if not results or not isinstance(results, list):
            adv_logger.log_warning("No results to export")
            return {}
            
        os.makedirs(self.results_dir, exist_ok=True)
        
        found_results = [r for r in results if isinstance(r, dict) and r.get("found", False)]
        
        if not found_results:
            adv_logger.log_info("No positive results to export")
            
        if not format_type:
            format_type = self.config.EXPORT_FORMATS[0] if self.config.EXPORT_FORMATS else "json"
            
        formats_to_export = []
        if format_type.lower() == "all":
            formats_to_export = self.supported_formats
        else:
            formats_to_export = [format_type.lower()]
            
        export_status = {}
        
        # If no custom filename provided, auto-generate from URL with timestamp
        if not base_filename:
            base_target_url = scan_info.get("target_url", "")
            if base_target_url:
                parsed = urlparse(base_target_url)
                base_domain = parsed.netloc
                timestamp = self._get_timestamp()
                base_filename = f"{base_domain}_{timestamp}" if base_domain else f"scan_{timestamp}"
        
        for fmt in formats_to_export:
            if fmt not in self.supported_formats:
                adv_logger.log_warning(f"Unsupported export format: {fmt}")
                export_status[fmt] = False
                continue
            
            # If custom filename provided, use it directly without timestamp
            if base_filename:
                safe_basename = os.path.basename(base_filename)
                
                # Check if filename already has an extension
                name_parts = os.path.splitext(safe_basename)
                if name_parts[1]:  # Has extension
                    # If extension matches format, use as-is
                    if name_parts[1].lower() == f".{fmt}":
                        filename = f"{self.results_dir}/{safe_basename}"
                    else:
                        # Has wrong extension, replace it with correct one
                        filename = f"{self.results_dir}/{name_parts[0]}.{fmt}"
                else:
                    # No extension, add it
                    filename = f"{self.results_dir}/{safe_basename}.{fmt}"
            else:
                # Auto-generate with timestamp
                filename = self._get_result_filename("", fmt)
            
            if fmt == "json":
                export_status[fmt] = self._export_json(results, scan_info, filename)
            elif fmt == "html":
                export_status[fmt] = self._export_html(results, scan_info, filename)
            elif fmt == "csv":
                export_status[fmt] = self._export_csv(results, scan_info, filename)
            elif fmt == "txt":
                export_status[fmt] = self._export_txt(results, scan_info, filename)
            else:
                adv_logger.log_warning(f"Format {fmt} recognized but no export function available")
                export_status[fmt] = False
                
        successful_formats = [f for f, status in export_status.items() if status]
        adv_logger.log_results_exported(successful_formats, len(found_results))
        
        return export_status
    
    def list_result_files(self) -> List[str]:
        try:
            if not os.path.exists(self.results_dir):
                return []
                
            result_files = []
            for filename in os.listdir(self.results_dir):
                if filename.endswith((".json", ".html", ".csv", ".txt")):
                    result_files.append(filename)
                    
            return sorted(result_files, reverse=True)
            
        except Exception as e:
            adv_logger.log_error(f"Failed to list result files: {str(e)}")
            return []
    
    def view_result_file(self, filename: str) -> str:

        try:
            filepath = os.path.join(self.results_dir, filename)
            
            if not os.path.exists(filepath):
                return ""
                
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
                
        except Exception as e:
            adv_logger.log_error(f"Failed to view result file: {str(e)}")
            return ""
