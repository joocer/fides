"""
Configuration management for Fides
"""
import os
from typing import Dict, Any, Optional
import json


class FidesConfig:
    """Configuration class for Fides scanner"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_default_config()
        if config_file and os.path.exists(config_file):
            self._load_config_file(config_file)
    
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            'scan': {
                'timeout': 30,
                'max_file_size': 10 * 1024 * 1024,  # 10MB
                'skip_extensions': [
                    '.pyc', '.pyo', '.pyd', '.so', '.dll', '.exe', '.bin',
                    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar', '.pdf',
                    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
                    '.mp3', '.mp4', '.avi', '.mov', '.wav'
                ],
                'skip_directories': [
                    '.git', '__pycache__', 'node_modules', '.pytest_cache',
                    '.coverage', 'dist', 'build', '.tox', '.venv', 'venv',
                    '.eggs', '*.egg-info'
                ]
            },
            'rules': {
                'default_url': (
                    "https://raw.githubusercontent.com/joocer/fides/main/rules/"
                    "Leaked%20Secrets%20(SECRETS).yar"
                )
            },
            'output': {
                'color': True,
                'verbose': False
            }
        }
    
    def _load_config_file(self, config_file: str):
        """Load configuration from file"""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                file_config = json.load(f)
                self._merge_config(self.config, file_config)
        except (json.JSONDecodeError, OSError) as e:
            print(f"Warning: Could not load config file {config_file}: {e}")
    
    def _merge_config(self, base: Dict[str, Any], override: Dict[str, Any]):
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation (e.g., 'scan.timeout')"""
        keys = key.split('.')
        value = self.config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default