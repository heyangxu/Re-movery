"""
Configuration settings for Movery
"""
import os
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class ProcessingConfig:
    # Number of parallel processes to use
    num_processes: int = os.cpu_count() or 4
    
    # Memory settings
    max_memory_usage: int = 8 * 1024 * 1024 * 1024  # 8GB
    chunk_size: int = 1024 * 1024  # 1MB
    
    # Cache settings
    enable_cache: bool = True
    cache_dir: str = ".cache"
    cache_max_size: int = 1024 * 1024 * 1024  # 1GB
    
    # Language support
    supported_languages: List[str] = ["c", "cpp", "java", "python", "go", "javascript"]
    file_extensions: Dict[str, List[str]] = {
        "c": [".c", ".h"],
        "cpp": [".cpp", ".hpp", ".cc", ".hh"],
        "java": [".java"],
        "python": [".py"],
        "go": [".go"],
        "javascript": [".js", ".jsx", ".ts", ".tsx"]
    }

@dataclass 
class DetectorConfig:
    # Vulnerability detection settings
    min_similarity: float = 0.8
    max_edit_distance: int = 10
    context_lines: int = 3
    
    # Analysis depth
    max_ast_depth: int = 50
    max_cfg_nodes: int = 1000
    
    # Pattern matching
    enable_semantic_match: bool = True
    enable_syntax_match: bool = True
    enable_token_match: bool = True
    
    # Reporting
    report_format: str = "html"
    report_dir: str = "reports"
    
    # Filtering
    exclude_patterns: List[str] = [
        "**/test/*",
        "**/tests/*", 
        "**/vendor/*",
        "**/node_modules/*"
    ]

@dataclass
class LoggingConfig:
    # Log settings
    log_level: str = "INFO"
    log_file: str = "movery.log"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Performance monitoring
    enable_profiling: bool = False
    profile_output: str = "profile.stats"
    
    # Progress reporting
    show_progress: bool = True
    progress_interval: int = 1  # seconds

@dataclass
class SecurityConfig:
    # Security settings
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    allowed_schemes: List[str] = ["file", "http", "https"]
    enable_sandbox: bool = True
    sandbox_timeout: int = 60  # seconds
    
    # Access control
    require_auth: bool = False
    auth_token: Optional[str] = None
    
    # Rate limiting
    rate_limit: int = 100  # requests per minute
    rate_limit_period: int = 60  # seconds

class MoveryConfig:
    def __init__(self):
        self.processing = ProcessingConfig()
        self.detector = DetectorConfig()
        self.logging = LoggingConfig()
        self.security = SecurityConfig()
        
    @classmethod
    def from_file(cls, config_file: str) -> "MoveryConfig":
        """Load configuration from file"""
        # TODO: Implement config file loading
        return cls()
        
    def to_file(self, config_file: str):
        """Save configuration to file"""
        # TODO: Implement config file saving
        pass
        
    def validate(self) -> bool:
        """Validate configuration settings"""
        # TODO: Add validation logic
        return True

# Global configuration instance
config = MoveryConfig() 