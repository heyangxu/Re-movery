"""
Code analysis utilities for Movery
"""
from typing import Dict, List, Optional
import os
import ast
import logging

from movery.utils.logging import get_logger
from movery.config.config import config
from .language import LanguageAnalyzer, PythonAnalyzer, JavaAnalyzer, CppAnalyzer, GoAnalyzer

logger = get_logger(__name__)

class CodeAnalyzer:
    """Code analyzer that supports multiple programming languages"""
    
    def __init__(self):
        self.analyzers = {
            ".py": PythonAnalyzer(),
            ".java": JavaAnalyzer(),
            ".cpp": CppAnalyzer(),
            ".hpp": CppAnalyzer(),
            ".cc": CppAnalyzer(),
            ".hh": CppAnalyzer(),
            ".go": GoAnalyzer()
        }
        
    def analyze_file(self, filename: str) -> Dict:
        """Analyze a source code file"""
        ext = os.path.splitext(filename)[1].lower()
        
        if ext not in self.analyzers:
            logger.warning(f"Unsupported file type: {ext}")
            return {
                "complexity": 0,
                "functions": [],
                "classes": [],
                "imports": [],
                "variables": []
            }
            
        analyzer = self.analyzers[ext]
        try:
            ast_node = analyzer.parse_file(filename)
            
            return {
                "complexity": self._calculate_complexity(ast_node),
                "functions": analyzer.get_functions(ast_node),
                "classes": analyzer.get_classes(ast_node),
                "imports": analyzer.get_imports(ast_node),
                "variables": analyzer.get_variables(ast_node)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing file {filename}: {str(e)}")
            return {
                "complexity": 0,
                "functions": [],
                "classes": [],
                "imports": [],
                "variables": []
            }
            
    def _calculate_complexity(self, ast_node: any) -> int:
        """Calculate code complexity"""
        # 简单实现 - 仅计算函数和类的数量
        if isinstance(ast_node, ast.AST):
            functions = sum(1 for node in ast.walk(ast_node) 
                          if isinstance(node, ast.FunctionDef))
            classes = sum(1 for node in ast.walk(ast_node)
                         if isinstance(node, ast.ClassDef))
            return functions + classes
        return 0 