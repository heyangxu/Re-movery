"""
Memory management utilities for Movery
"""
import os
import mmap
import psutil
import gc
from typing import Optional, Generator, Any
from contextlib import contextmanager
import threading
import weakref
from collections import OrderedDict
import logging

from ..config.config import config

logger = logging.getLogger(__name__)

class MemoryMonitor:
    """Monitor memory usage and enforce limits"""
    
    def __init__(self, max_memory: Optional[int] = None):
        self.max_memory = max_memory or config.processing.max_memory_usage
        self.process = psutil.Process()
        self._lock = threading.Lock()
        self._last_check = 0
        
    def get_memory_usage(self) -> int:
        """Get current memory usage in bytes"""
        return self.process.memory_info().rss
        
    def check_memory(self) -> bool:
        """Check if memory usage is within limits"""
        with self._lock:
            current_usage = self.get_memory_usage()
            if current_usage > self.max_memory:
                logger.warning(f"Memory usage ({current_usage} bytes) exceeds limit "
                             f"({self.max_memory} bytes)")
                return False
            return True
            
    def force_garbage_collection(self):
        """Force garbage collection"""
        gc.collect()
        
    @contextmanager
    def monitor_operation(self, operation_name: str):
        """Context manager to monitor memory during an operation"""
        start_usage = self.get_memory_usage()
        try:
            yield
        finally:
            end_usage = self.get_memory_usage()
            delta = end_usage - start_usage
            logger.debug(f"Memory delta for {operation_name}: {delta} bytes")
            if not self.check_memory():
                self.force_garbage_collection()

class LRUCache:
    """Least Recently Used Cache with memory limit"""
    
    def __init__(self, max_size: Optional[int] = None):
        self.max_size = max_size or config.processing.cache_max_size
        self._cache = OrderedDict()
        self._size = 0
        self._lock = threading.Lock()
        
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache"""
        with self._lock:
            if key in self._cache:
                value = self._cache.pop(key)
                self._cache[key] = value
                return value
            return None
            
    def put(self, key: str, value: Any, size: Optional[int] = None):
        """Put item in cache"""
        if not size:
            size = sys.getsizeof(value)
            
        if size > self.max_size:
            logger.warning(f"Item size ({size} bytes) exceeds cache limit "
                         f"({self.max_size} bytes)")
            return
            
        with self._lock:
            if key in self._cache:
                self._size -= sys.getsizeof(self._cache[key])
                
            while self._size + size > self.max_size and self._cache:
                _, removed = self._cache.popitem(last=False)
                self._size -= sys.getsizeof(removed)
                
            self._cache[key] = value
            self._size += size
            
    def clear(self):
        """Clear cache"""
        with self._lock:
            self._cache.clear()
            self._size = 0

class MemoryMappedFile:
    """Memory mapped file for efficient large file handling"""
    
    def __init__(self, filename: str, mode: str = "r"):
        self.filename = filename
        self.mode = mode
        self._file = None
        self._mmap = None
        
    def __enter__(self):
        access = mmap.ACCESS_READ
        if "w" in self.mode:
            access = mmap.ACCESS_WRITE
            
        self._file = open(self.filename, mode=self.mode + "b")
        self._mmap = mmap.mmap(self._file.fileno(), 0, access=access)
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._mmap:
            self._mmap.close()
        if self._file:
            self._file.close()
            
    def read(self, size: int = -1) -> bytes:
        """Read from memory mapped file"""
        if size == -1:
            return self._mmap[:]
        return self._mmap[:size]
        
    def write(self, data: bytes):
        """Write to memory mapped file"""
        if "w" not in self.mode:
            raise IOError("File not opened for writing")
        self._mmap.write(data)
        
    def seek(self, offset: int):
        """Seek to position in file"""
        self._mmap.seek(offset)

def chunk_iterator(data: Any, chunk_size: Optional[int] = None) -> Generator:
    """Iterator that yields chunks of data"""
    if not chunk_size:
        chunk_size = config.processing.chunk_size
        
    if isinstance(data, (bytes, str)):
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]
    elif hasattr(data, "__iter__"):
        chunk = []
        for item in data:
            chunk.append(item)
            if len(chunk) >= chunk_size:
                yield chunk
                chunk = []
        if chunk:
            yield chunk
    else:
        raise TypeError(f"Unsupported data type: {type(data)}")

# Global memory monitor instance
memory_monitor = MemoryMonitor()

# Global cache instance
cache = LRUCache() 