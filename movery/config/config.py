"""
Configuration module for Movery
"""
import json
import os
from typing import Dict, Any, List
from dataclasses import dataclass

@dataclass
class ProcessingConfig:
    num_processes: int
    max_memory_usage: int
    chunk_size: int
    enable_cache: bool
    cache_dir: str
    cache_max_size: int
    supported_languages: List[str]

@dataclass
class DetectorConfig:
    min_similarity: float
    max_edit_distance: int
    context_lines: int
    max_ast_depth: int
    max_cfg_nodes: int
    enable_semantic_match: bool
    enable_syntax_match: bool
    enable_token_match: bool
    report_format: str
    report_dir: str
    exclude_patterns: List[str]

@dataclass
class LoggingConfig:
    log_level: str
    log_file: str
    log_format: str
    enable_profiling: bool
    profile_output: str
    show_progress: bool
    progress_interval: int

@dataclass
class SecurityConfig:
    max_file_size: int
    allowed_schemes: List[str]
    enable_sandbox: bool
    sandbox_timeout: int
    require_auth: bool
    rate_limit: int
    rate_limit_period: int

@dataclass
class Config:
    processing: ProcessingConfig
    detector: DetectorConfig
    logging: LoggingConfig
    security: SecurityConfig

def load_config(config_path: str = None) -> Config:
    """
    Load configuration from JSON file
    
    Args:
        config_path: Path to config file. If None, uses default config.json
        
    Returns:
        Configuration object
    """
    if config_path is None:
        config_path = os.path.join(os.path.dirname(__file__), "config.json")
        
    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    return Config(
        processing=ProcessingConfig(**data["processing"]),
        detector=DetectorConfig(**data["detector"]),
        logging=LoggingConfig(**data["logging"]),
        security=SecurityConfig(**data["security"])
    )

# Load default configuration
config = load_config() 