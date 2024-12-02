"""
Re-Movery - A tool for discovering modified vulnerable code clones
"""

__version__ = "1.0.0"
__author__ = "heyangxu"
__email__ = ""

from .config.config import config
from .detectors.vulnerability import detector
from .reporters.html import reporter

__all__ = ["config", "detector", "reporter"] 