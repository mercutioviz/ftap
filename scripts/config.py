import os
import json
import logging
from dataclasses import dataclass, field
from typing import List, Dict

from scripts.logging import get_logger

adv_logger = get_logger('logs')

@dataclass
class Config:
    VERSION: str = ""
    DEVELOPER: str = ""
    GITHUB: str = ""
    TOOL_NAME: str = ""
    RELEASE_DATE: str = ""
    CACHE_TTL: int = 0
    CACHE_SIZE: int = 0
    MAX_CONCURRENT_TASKS: int = 0
    CONNECTION_TIMEOUT: int = 0
    READ_TIMEOUT: int = 0
    BATCH_SIZE: int = 0
    VERIFY_SSL: bool = False
    MAX_RETRIES: int = 0
    RETRY_DELAY: float = 0.0
    RETRY_JITTER: float = 0.0
    MAX_CONCURRENT_RETRIES: int = 0
    TIMEOUT_BACKOFF_FACTOR: float = 0.0
    AUTO_ADJUST_CONCURRENCY: bool = False
    MAX_TIMEOUT_THRESHOLD: int = 0
    USE_PROXIES: bool = False
    USE_HEADLESS_BROWSER: bool = False
    CAPTCHA_DETECTION: bool = False
    EXPORT_FORMATS: List[str] = field(default_factory=list)
    DETECTION_MODES: List[str] = field(default_factory=list)
    DETECTION_MODE: str = ""
    SCAN_FREQUENCY: str = ""
    MULTI_SITE_SCAN: bool = False
    LOGS_DIR: str = ""
    CUSTOM_PATHS_FILE: str = ""
    DEFAULT_WORDLIST: str = ""  
    MAX_PATHS: int = 0
    SAVE_RESULTS: bool = False
    RESULTS_DIR: str = ""
    USER_AGENTS: List[str] = field(default_factory=list)
    PROXIES: List[str] = field(default_factory=list)
    HEADERS_EXTRA: Dict[str, str] = field(default_factory=dict)
    USE_HTTP3: bool = False
    USE_ML_DETECTION: bool = False
    USE_PATH_FUZZING: bool = False
    AUTO_UPDATE_WORDLIST: bool = False
    WORDLIST_UPDATE_INTERVAL: int = 7
    WORDLIST_UPDATE_SOURCE: str = ""
    CACHE_PERSISTENT: bool = False
    MULTILINGUAL_SUPPORT: bool = False
    BENCHMARK_MODE: bool = False
    
    MODE_CONFIGS: Dict[str, Dict] = field(default_factory=dict)
    
    def __post_init__(self):
        self.load_config()
        self._validate_and_set_defaults()
        self._setup_detection_modes()
    
    def _validate_and_set_defaults(self):
        if not self.USER_AGENTS:
            default_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15'
            ]
            self.USER_AGENTS = default_agents
            adv_logger.log_warning("USER_AGENTS not found in config.json or was empty. Using default user agents.")
            
            try:
                config_file = "config/config.json"
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        config_data = json.load(f)
                    
                    config_data['USER_AGENTS'] = default_agents
                    
                    with open(config_file, 'w') as f:
                        json.dump(config_data, f, indent=4)
                    
                    adv_logger.log_info("Updated config.json with default USER_AGENTS")
            except Exception as e:
                adv_logger.log_error(f"Failed to update config.json with default USER_AGENTS: {str(e)}")
        else:
            adv_logger.log_info(f"Using {len(self.USER_AGENTS)} user agents from config.json")
            
        if not self.DEFAULT_WORDLIST:
            self.DEFAULT_WORDLIST = "paths/general_paths.json"
            adv_logger.log_info(f"Using default wordlist path: {self.DEFAULT_WORDLIST}")
            
            try:
                config_file = "config/config.json"
                if os.path.exists(config_file):
                    with open(config_file, 'r') as f:
                        config_data = json.load(f)
                    
                    config_data['DEFAULT_WORDLIST'] = self.DEFAULT_WORDLIST
                    
                    with open(config_file, 'w') as f:
                        json.dump(config_data, f, indent=4)
                    
                    adv_logger.log_info("Updated config.json with DEFAULT_WORDLIST")
            except Exception as e:
                adv_logger.log_error(f"Failed to update config.json with DEFAULT_WORDLIST: {str(e)}")
                
        os.makedirs(self.LOGS_DIR, exist_ok=True)
        os.makedirs(self.RESULTS_DIR, exist_ok=True)
        os.makedirs(os.path.dirname(self.DEFAULT_WORDLIST), exist_ok=True)
        
    def _setup_detection_modes(self):
        self.MODE_CONFIGS = {
            "simple": {
                "MAX_CONCURRENT_TASKS": 50,
                "CONNECTION_TIMEOUT": 5,
                "READ_TIMEOUT": 10,
                "DELAY_BETWEEN_REQUESTS": 0.0,
                "REQUEST_RANDOMIZATION": False,
                "CONFIDENCE_THRESHOLD": 0.6,
                "MAX_RETRIES": 2,
                "USE_RANDOM_USER_AGENTS": False,
                "VERIFY_FOUND_URLS": False,
                "DESCRIPTION": "Fast scanning with minimal evasion techniques"
            },
            "stealth": {
                "MAX_CONCURRENT_TASKS": 3,
                "CONNECTION_TIMEOUT": 10,
                "READ_TIMEOUT": 15,
                "DELAY_BETWEEN_REQUESTS": 2.0,
                "REQUEST_RANDOMIZATION": True,
                "CONFIDENCE_THRESHOLD": 0.65,
                "MAX_RETRIES": 0,
                "USE_RANDOM_USER_AGENTS": True,
                "VERIFY_FOUND_URLS": True,
                "DESCRIPTION": "Slow scanning to avoid detection, with advanced evasion techniques"
            },
            "aggressive": {
                "MAX_CONCURRENT_TASKS": 150,
                "CONNECTION_TIMEOUT": 3,
                "READ_TIMEOUT": 5,
                "DELAY_BETWEEN_REQUESTS": 0.0,
                "REQUEST_RANDOMIZATION": False,
                "CONFIDENCE_THRESHOLD": 0.55,
                "MAX_RETRIES": 3,
                "USE_RANDOM_USER_AGENTS": True,
                "VERIFY_FOUND_URLS": True,
                "DESCRIPTION": "Maximum speed scanning with minimal consideration for detection"
            }
        }
        
        if self.DETECTION_MODE in self.MODE_CONFIGS:
            mode_config = self.MODE_CONFIGS[self.DETECTION_MODE]
            self.MAX_CONCURRENT_TASKS = mode_config.get("MAX_CONCURRENT_TASKS", self.MAX_CONCURRENT_TASKS)
            self.CONNECTION_TIMEOUT = mode_config.get("CONNECTION_TIMEOUT", self.CONNECTION_TIMEOUT)
            self.READ_TIMEOUT = mode_config.get("READ_TIMEOUT", self.READ_TIMEOUT)
            
            adv_logger.log_info(f"Applied {self.DETECTION_MODE} mode configuration with {self.MAX_CONCURRENT_TASKS} concurrent tasks")
    
    def save_config(self, filepath: str = "config/config.json"):
        config_dict = {
            key: value for key, value in self.__dict__.items() 
            if not key.startswith('_') and not callable(value) and key != 'MODE_CONFIGS'
        }
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
        with open(filepath, 'w') as f:
            json.dump(config_dict, f, indent=4)
            
    def load_config(self, filepath: str = "config/config.json"):
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    config_data = json.load(f)
                
                for key, value in config_data.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
                
                adv_logger.log_info(f"Configuration loaded from {filepath}")
            else:
                adv_logger.log_warning(f"Configuration file {filepath} not found, using defaults")
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                
        except json.JSONDecodeError as e:
            adv_logger.log_error(f"Error parsing configuration file {filepath}: {str(e)}")
        except Exception as e:
            adv_logger.log_error(f"Error loading configuration: {str(e)}")
            
    def get_current_mode_config(self):
        return self.MODE_CONFIGS.get(self.DETECTION_MODE, {})

def setup_logging(config):
    global adv_logger
    
    os.makedirs(config.LOGS_DIR, exist_ok=True)
    
    if adv_logger is None:
        adv_logger = get_logger(config.LOGS_DIR)
    
    adv_logger.log_info(f"Logging system initialized for {config.TOOL_NAME} v{config.VERSION}")
    
    return adv_logger

def setup_directories(config):
    directories = [
        config.LOGS_DIR,
        config.RESULTS_DIR,
        os.path.dirname(config.CUSTOM_PATHS_FILE)
    ]
    
    try:
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                adv_logger.log_info(f"Created directory: {directory}")
                
        if not os.path.exists(config.CUSTOM_PATHS_FILE):
            adv_logger.log_warning(f"General paths file {config.CUSTOM_PATHS_FILE} not found, creating a minimal version")
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
        adv_logger.log_error(f"Failed to create directories: {str(e)}")
        return False

def load_paths(config) -> List[str]:
    paths_file = config.CUSTOM_PATHS_FILE
    paths = []
    
    try:
        paths_dir = os.path.dirname(paths_file)
        if not os.path.exists(paths_dir):
            os.makedirs(paths_dir)
            adv_logger.log_info(f"Created paths directory: {paths_dir}")
        
        if not os.path.exists(paths_file):
            adv_logger.log_warning(f"General paths file not found: {paths_file}")
            return []
            
        with open(paths_file, 'r') as f:
            data = json.load(f)
            
        if not isinstance(data, list):
            adv_logger.log_error(f"Invalid format in {paths_file}. Expected a list.")
            return []
            
        paths = data
        
        total_available_paths = len(paths)
        
        max_paths = config.MAX_PATHS
        if max_paths > 0 and max_paths < total_available_paths:
            paths = paths[:max_paths]
            adv_logger.log_info(f"Limiting paths to {max_paths} (from {total_available_paths} available)")
        elif max_paths > 0:
            adv_logger.log_info(f"Using all {total_available_paths} available paths")
        else:
            adv_logger.log_info(f"Using all {total_available_paths} available paths (no limit set)")
        
        adv_logger.log_info(f"Loaded {len(paths)} paths from {paths_file}")
        return paths
    except json.JSONDecodeError as e:
        adv_logger.log_error(f"Error parsing JSON in {paths_file}: {str(e)}")
        return []
    except Exception as e:
        adv_logger.log_error(f"Error loading paths: {str(e)}")
        return [] 
