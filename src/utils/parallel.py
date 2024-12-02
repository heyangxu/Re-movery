"""
Parallel processing utilities for Movery
"""
import multiprocessing as mp
from multiprocessing import Pool, Queue, Manager
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import threading
from typing import Callable, List, Any, Optional, Dict, Tuple
import time
import os
import signal
import logging
from functools import partial
import queue
import traceback

from ..config.config import config
from .logging import get_logger

logger = get_logger(__name__)

class WorkerPool:
    """Pool of worker processes with task queue"""
    
    def __init__(self, num_workers: Optional[int] = None,
                 use_threads: bool = False):
        self.num_workers = num_workers or config.processing.num_processes
        self.use_threads = use_threads
        self._pool = None
        self._manager = None
        self._task_queue = None
        self._result_queue = None
        self._workers = []
        self._running = False
        self._lock = threading.Lock() if use_threads else mp.Lock()
        
    def start(self):
        """Start worker pool"""
        if self._running:
            return
            
        self._manager = Manager() if not self.use_threads else None
        self._task_queue = Queue() if not self.use_threads else queue.Queue()
        self._result_queue = Queue() if not self.use_threads else queue.Queue()
        
        if self.use_threads:
            self._pool = ThreadPoolExecutor(max_workers=self.num_workers)
        else:
            self._pool = ProcessPoolExecutor(max_workers=self.num_workers)
            
        self._running = True
        logger.info(f"Started worker pool with {self.num_workers} workers")
        
    def stop(self):
        """Stop worker pool"""
        if not self._running:
            return
            
        self._running = False
        if self._pool:
            self._pool.shutdown()
        if self._manager:
            self._manager.shutdown()
            
        logger.info("Stopped worker pool")
        
    def submit(self, func: Callable, *args, **kwargs) -> Any:
        """Submit task to worker pool"""
        if not self._running:
            raise RuntimeError("Worker pool not started")
            
        future = self._pool.submit(func, *args, **kwargs)
        return future
        
    def map(self, func: Callable, iterable: List[Any]) -> List[Any]:
        """Map function over iterable using worker pool"""
        if not self._running:
            raise RuntimeError("Worker pool not started")
            
        return list(self._pool.map(func, iterable))
        
    def imap(self, func: Callable, iterable: List[Any]) -> Any:
        """Iterator over mapped function results"""
        if not self._running:
            raise RuntimeError("Worker pool not started")
            
        for result in self._pool.map(func, iterable):
            yield result
            
    @contextmanager
    def get_context(self):
        """Context manager for worker pool"""
        self.start()
        try:
            yield self
        finally:
            self.stop()

class TaskQueue:
    """Task queue with priority support"""
    
    def __init__(self, maxsize: int = 0):
        self.maxsize = maxsize
        self._queue = PriorityQueue(maxsize=maxsize)
        self._unfinished_tasks = 0
        self._mutex = threading.Lock()
        self._not_empty = threading.Condition(self._mutex)
        self._not_full = threading.Condition(self._mutex)
        self._all_tasks_done = threading.Condition(self._mutex)
        
    def put(self, item: Any, priority: int = 0, block: bool = True,
            timeout: Optional[float] = None):
        """Put item in queue with priority"""
        with self._not_full:
            if self.maxsize > 0:
                if not block:
                    if self._qsize() >= self.maxsize:
                        raise queue.Full
                elif timeout is None:
                    while self._qsize() >= self.maxsize:
                        self._not_full.wait()
                elif timeout < 0:
                    raise ValueError("'timeout' must be a non-negative number")
                else:
                    endtime = time.time() + timeout
                    while self._qsize() >= self.maxsize:
                        remaining = endtime - time.time()
                        if remaining <= 0.0:
                            raise queue.Full
                        self._not_full.wait(remaining)
                        
            self._queue.put((priority, item))
            self._unfinished_tasks += 1
            self._not_empty.notify()
            
    def get(self, block: bool = True, timeout: Optional[float] = None) -> Any:
        """Get item from queue"""
        with self._not_empty:
            if not block:
                if not self._qsize():
                    raise queue.Empty
            elif timeout is None:
                while not self._qsize():
                    self._not_empty.wait()
            elif timeout < 0:
                raise ValueError("'timeout' must be a non-negative number")
            else:
                endtime = time.time() + timeout
                while not self._qsize():
                    remaining = endtime - time.time()
                    if remaining <= 0.0:
                        raise queue.Empty
                    self._not_empty.wait(remaining)
                    
            item = self._queue.get()[1]
            self._not_full.notify()
            return item
            
    def task_done(self):
        """Indicate that a task is done"""
        with self._all_tasks_done:
            unfinished = self._unfinished_tasks - 1
            if unfinished < 0:
                raise ValueError("task_done() called too many times")
            self._unfinished_tasks = unfinished
            if unfinished == 0:
                self._all_tasks_done.notify_all()
                
    def join(self):
        """Wait for all tasks to be done"""
        with self._all_tasks_done:
            while self._unfinished_tasks:
                self._all_tasks_done.wait()
                
    def qsize(self) -> int:
        """Return queue size"""
        return self._queue.qsize()
        
    def empty(self) -> bool:
        """Return True if queue is empty"""
        return self._queue.empty()
        
    def full(self) -> bool:
        """Return True if queue is full"""
        return self._queue.full()
        
    def _qsize(self) -> int:
        """Internal method to get queue size"""
        return self._queue.qsize()

class ParallelExecutor:
    """Execute tasks in parallel with error handling"""
    
    def __init__(self, num_workers: Optional[int] = None,
                 use_threads: bool = False):
        self.worker_pool = WorkerPool(num_workers, use_threads)
        self.task_queue = TaskQueue()
        self._results = {}
        self._errors = {}
        self._lock = threading.Lock()
        
    def submit(self, task_id: str, func: Callable, *args,
               priority: int = 0, **kwargs) -> None:
        """Submit task for execution"""
        self.task_queue.put((task_id, func, args, kwargs), priority=priority)
        
    def execute(self) -> Tuple[Dict[str, Any], Dict[str, Exception]]:
        """Execute all submitted tasks"""
        with self.worker_pool.get_context():
            while not self.task_queue.empty():
                try:
                    task_id, func, args, kwargs = self.task_queue.get()
                    future = self.worker_pool.submit(func, *args, **kwargs)
                    future.add_done_callback(
                        partial(self._handle_result, task_id))
                except Exception as e:
                    logger.error(f"Error executing task {task_id}: {str(e)}")
                    with self._lock:
                        self._errors[task_id] = e
                finally:
                    self.task_queue.task_done()
                    
            self.task_queue.join()
            return self._results, self._errors
            
    def _handle_result(self, task_id: str, future):
        """Handle task result or error"""
        try:
            result = future.result()
            with self._lock:
                self._results[task_id] = result
        except Exception as e:
            logger.error(f"Error in task {task_id}: {str(e)}")
            with self._lock:
                self._errors[task_id] = e

def parallel_map(func: Callable, iterable: List[Any],
                num_workers: Optional[int] = None,
                chunk_size: Optional[int] = None) -> List[Any]:
    """Map function over iterable in parallel"""
    if not num_workers:
        num_workers = config.processing.num_processes
    if not chunk_size:
        chunk_size = max(1, len(iterable) // (num_workers * 4))
        
    with Pool(processes=num_workers) as pool:
        return pool.map(func, iterable, chunksize=chunk_size)

# Global worker pool instance
worker_pool = WorkerPool() 