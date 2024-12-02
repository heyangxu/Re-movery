"""
Main entry point for Movery
"""
import os
import sys
import argparse
import logging
import json
from typing import List, Dict, Optional
import time
from pathlib import Path
import concurrent.futures
import traceback

from .config.config import config, MoveryConfig
from .utils.logging import setup_logging, get_logger
from .utils.memory import memory_monitor
from .utils.parallel import worker_pool
from .analyzers.language import LanguageAnalyzerFactory
from .detectors.vulnerability import detector
from .reporters.html import reporter

logger = get_logger(__name__)

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Movery - A tool for discovering modified vulnerable code clones"
    )
    
    parser.add_argument(
        "target",
        help="Target program or directory to analyze"
    )
    
    parser.add_argument(
        "-c", "--config",
        help="Path to configuration file",
        default="config.json"
    )
    
    parser.add_argument(
        "-s", "--signatures",
        help="Path to vulnerability signatures file",
        default="signatures.json"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output directory for reports",
        default="reports"
    )
    
    parser.add_argument(
        "-j", "--jobs",
        help="Number of parallel jobs",
        type=int,
        default=None
    )
    
    parser.add_argument(
        "-v", "--verbose",
        help="Enable verbose output",
        action="store_true"
    )
    
    parser.add_argument(
        "--cache",
        help="Enable result caching",
        action="store_true"
    )
    
    return parser.parse_args()

def load_config(config_file: str) -> MoveryConfig:
    """Load configuration from file"""
    if os.path.exists(config_file):
        return MoveryConfig.from_file(config_file)
    return MoveryConfig()

def find_source_files(target: str) -> List[str]:
    """Find all source files in target"""
    source_files = []
    
    for root, _, files in os.walk(target):
        for file in files:
            file_path = os.path.join(root, file)
            
            # Skip files larger than limit
            if os.path.getsize(file_path) > config.security.max_file_size:
                logger.warning(f"Skipping large file: {file_path}")
                continue
                
            # Skip files matching exclude patterns
            skip = False
            for pattern in config.detector.exclude_patterns:
                if Path(file_path).match(pattern):
                    skip = True
                    break
            if skip:
                continue
                
            # Check if file is supported
            if LanguageAnalyzerFactory.get_analyzer(file_path):
                source_files.append(file_path)
                
    return source_files

def analyze_file(file: str) -> List[Dict]:
    """Analyze single file for vulnerabilities"""
    try:
        matches = detector.detect(file)
        return [match.to_dict() for match in matches]
    except Exception as e:
        logger.error(f"Error analyzing file {file}: {str(e)}")
        logger.debug(traceback.format_exc())
        return []

def main():
    """Main entry point"""
    start_time = time.time()
    
    # Parse arguments
    args = parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level=log_level)
    
    logger.info("Starting Movery...")
    
    try:
        # Load configuration
        config = load_config(args.config)
        if args.jobs:
            config.processing.num_processes = args.jobs
        config.processing.enable_cache = args.cache
        
        # Load vulnerability signatures
        detector.load_signatures(args.signatures)
        
        # Find source files
        target_path = os.path.abspath(args.target)
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target not found: {target_path}")
            
        logger.info(f"Analyzing target: {target_path}")
        source_files = find_source_files(target_path)
        logger.info(f"Found {len(source_files)} source files")
        
        # Start worker pool
        worker_pool.start()
        
        # Process files in parallel
        all_matches = []
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=config.processing.num_processes
        ) as executor:
            future_to_file = {
                executor.submit(analyze_file, file): file
                for file in source_files
            }
            
            for future in concurrent.futures.as_completed(future_to_file):
                file = future_to_file[future]
                try:
                    matches = future.result()
                    if matches:
                        all_matches.extend(matches)
                        logger.info(
                            f"Found {len(matches)} vulnerabilities in {file}")
                except Exception as e:
                    logger.error(f"Error processing {file}: {str(e)}")
                    
        # Generate report
        if all_matches:
            os.makedirs(args.output, exist_ok=True)
            report_file = os.path.join(
                args.output,
                f"report_{int(time.time())}.html"
            )
            reporter.generate_report(all_matches, report_file)
            logger.info(f"Generated report: {report_file}")
        else:
            logger.info("No vulnerabilities found")
            
        elapsed_time = time.time() - start_time
        logger.info(f"Analysis completed in {elapsed_time:.2f} seconds")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        logger.debug(traceback.format_exc())
        sys.exit(1)
    finally:
        worker_pool.stop()

if __name__ == "__main__":
    main() 