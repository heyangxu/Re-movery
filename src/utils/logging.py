"""
Logging utilities for Movery
"""
import logging
import sys
import os
import time
from typing import Optional
from datetime import datetime
from functools import wraps
import threading
from concurrent.futures import ThreadPoolExecutor
import queue
import json

from ..config.config import config

class AsyncLogHandler(logging.Handler):
    """Asynchronous log handler that processes logs in a separate thread"""
    
    def __init__(self, capacity: int = 1000):
        super().__init__()
        self.queue = queue.Queue(maxsize=capacity)
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.running = True
        self.worker = threading.Thread(target=self._process_logs)
        self.worker.daemon = True
        self.worker.start()
        
    def emit(self, record: logging.LogRecord):
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            sys.stderr.write(f"Log queue full, dropping message: {record.getMessage()}\n")
            
    def _process_logs(self):
        while self.running:
            try:
                record = self.queue.get(timeout=0.1)
                self.executor.submit(self._write_log, record)
            except queue.Empty:
                continue
            except Exception as e:
                sys.stderr.write(f"Error processing log: {str(e)}\n")
                
    def _write_log(self, record: logging.LogRecord):
        try:
            message = self.format(record)
            with open(config.logging.log_file, "a", encoding="utf-8") as f:
                f.write(message + "\n")
        except Exception as e:
            sys.stderr.write(f"Error writing log: {str(e)}\n")
            
    def close(self):
        self.running = False
        self.worker.join()
        self.executor.shutdown()
        super().close()

class ProgressLogger:
    """Logger for tracking and displaying progress"""
    
    def __init__(self, total: int, desc: str = "", interval: float = 0.1):
        self.total = total
        self.desc = desc
        self.interval = interval
        self.current = 0
        self.start_time = time.time()
        self.last_update = 0
        
    def update(self, n: int = 1):
        self.current += n
        now = time.time()
        if now - self.last_update >= self.interval:
            self._display_progress()
            self.last_update = now
            
    def _display_progress(self):
        percentage = (self.current / self.total) * 100
        elapsed = time.time() - self.start_time
        rate = self.current / elapsed if elapsed > 0 else 0
        eta = (self.total - self.current) / rate if rate > 0 else 0
        
        sys.stdout.write(f"\r{self.desc}: [{self.current}/{self.total}] "
                        f"{percentage:.1f}% Rate: {rate:.1f}/s ETA: {eta:.1f}s")
        sys.stdout.flush()
        
    def finish(self):
        self._display_progress()
        sys.stdout.write("\n")
        sys.stdout.flush()

class JsonFormatter(logging.Formatter):
    """Format logs as JSON for better parsing"""
    
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        if record.exc_info:
            data["exception"] = self.formatException(record.exc_info)
            
        if hasattr(record, "extra"):
            data.update(record.extra)
            
        return json.dumps(data)

def setup_logging(log_file: Optional[str] = None):
    """Setup logging configuration"""
    if log_file:
        config.logging.log_file = log_file
        
    # Create log directory if needed
    os.makedirs(os.path.dirname(config.logging.log_file), exist_ok=True)
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(config.logging.log_level)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(config.logging.log_format)
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler
    file_handler = AsyncLogHandler()
    file_handler.setLevel(logging.DEBUG)
    file_formatter = JsonFormatter()
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
def log_execution_time(logger: Optional[logging.Logger] = None):
    """Decorator to log function execution time"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            elapsed_time = time.time() - start_time
            
            log = logger or logging.getLogger(func.__module__)
            log.debug(f"{func.__name__} executed in {elapsed_time:.2f} seconds")
            
            return result
        return wrapper
    return decorator

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with the given name"""
    return logging.getLogger(name)

# Initialize logging when module is imported
setup_logging() 