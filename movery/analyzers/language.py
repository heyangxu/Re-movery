"""
Language analysis utilities for Movery
"""
import os
from typing import Dict, List, Optional, Set, Tuple, Any
import re
import ast
import tokenize
from io import StringIO
import logging
import subprocess
from abc import ABC, abstractmethod
import tempfile
import json

from movery.config.config import config
from movery.utils.logging import get_logger
from movery.utils.memory import MemoryMappedFile, MemoryMonitor

logger = get_logger(__name__)

class LanguageAnalyzer(ABC):
    """Base class for language analyzers"""
    
    def __init__(self):
        self.file_extensions = []
        
    @abstractmethod
    def parse_file(self, filename: str) -> Any:
        """Parse source file and return AST"""
        pass
        
    @abstractmethod
    def get_functions(self, ast_node: Any) -> List[Dict]:
        """Extract functions from AST"""
        pass
        
    @abstractmethod
    def get_classes(self, ast_node: Any) -> List[Dict]:
        """Extract classes from AST"""
        pass
        
    @abstractmethod
    def get_imports(self, ast_node: Any) -> List[Dict]:
        """Extract imports from AST"""
        pass
        
    @abstractmethod
    def get_variables(self, ast_node: Any) -> List[Dict]:
        """Extract variables from AST"""
        pass
        
    def supports_file(self, filename: str) -> bool:
        """Check if file is supported by this analyzer"""
        ext = os.path.splitext(filename)[1].lower()
        return ext in self.file_extensions

class PythonAnalyzer(LanguageAnalyzer):
    """Python source code analyzer"""
    
    def __init__(self):
        super().__init__()
        self.file_extensions = [".py"]
        
    def parse_file(self, filename: str) -> ast.AST:
        """Parse Python source file"""
        with open(filename, "r", encoding="utf-8") as f:
            return ast.parse(f.read(), filename=filename)
            
    def get_functions(self, ast_node: ast.AST) -> List[Dict]:
        """Extract functions from Python AST"""
        functions = []
        for node in ast.walk(ast_node):
            if isinstance(node, ast.FunctionDef):
                func = {
                    "name": node.name,
                    "lineno": node.lineno,
                    "args": [arg.arg for arg in node.args.args],
                    "returns": self._get_return_annotation(node),
                    "docstring": ast.get_docstring(node),
                    "decorators": [self._get_decorator_name(d) for d in node.decorator_list]
                }
                functions.append(func)
        return functions
        
    def get_classes(self, ast_node: ast.AST) -> List[Dict]:
        """Extract classes from Python AST"""
        classes = []
        for node in ast.walk(ast_node):
            if isinstance(node, ast.ClassDef):
                cls = {
                    "name": node.name,
                    "lineno": node.lineno,
                    "bases": [self._get_name(b) for b in node.bases],
                    "docstring": ast.get_docstring(node),
                    "methods": self.get_functions(node),
                    "decorators": [self._get_decorator_name(d) for d in node.decorator_list]
                }
                classes.append(cls)
        return classes
        
    def get_imports(self, ast_node: ast.AST) -> List[Dict]:
        """Extract imports from Python AST"""
        imports = []
        for node in ast.walk(ast_node):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports.append({
                        "module": name.name,
                        "alias": name.asname,
                        "lineno": node.lineno
                    })
            elif isinstance(node, ast.ImportFrom):
                for name in node.names:
                    imports.append({
                        "module": node.module,
                        "name": name.name,
                        "alias": name.asname,
                        "lineno": node.lineno
                    })
        return imports
        
    def get_variables(self, ast_node: ast.AST) -> List[Dict]:
        """Extract variables from Python AST"""
        variables = []
        for node in ast.walk(ast_node):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var = {
                            "name": target.id,
                            "lineno": node.lineno,
                            "value": self._get_value(node.value)
                        }
                        variables.append(var)
        return variables
        
    def _get_return_annotation(self, node: ast.FunctionDef) -> Optional[str]:
        """Get function return type annotation"""
        if node.returns:
            return self._get_name(node.returns)
        return None
        
    def _get_decorator_name(self, node: ast.expr) -> str:
        """Get decorator name"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Call):
            return self._get_name(node.func)
        elif isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        return str(node)
        
    def _get_name(self, node: ast.expr) -> str:
        """Get name from AST node"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        return str(node)
        
    def _get_value(self, node: ast.expr) -> Any:
        """Get value from AST node"""
        if isinstance(node, (ast.Num, ast.Str, ast.Bytes)):
            return node.n if isinstance(node, ast.Num) else node.s
        elif isinstance(node, ast.NameConstant):
            return node.value
        elif isinstance(node, ast.List):
            return [self._get_value(elt) for elt in node.elts]
        elif isinstance(node, ast.Dict):
            return {self._get_value(k): self._get_value(v)
                   for k, v in zip(node.keys, node.values)}
        return None

class JavaAnalyzer(LanguageAnalyzer):
    """Java source code analyzer"""
    
    def __init__(self):
        super().__init__()
        self.file_extensions = [".java"]
        
    def parse_file(self, filename: str) -> Dict:
        """Parse Java source file using external parser"""
        # Use JavaParser or similar tool
        # This is a placeholder implementation
        return {}
        
    def get_functions(self, ast_node: Dict) -> List[Dict]:
        """Extract methods from Java AST"""
        # Placeholder implementation
        return []
        
    def get_classes(self, ast_node: Dict) -> List[Dict]:
        """Extract classes from Java AST"""
        # Placeholder implementation
        return []
        
    def get_imports(self, ast_node: Dict) -> List[Dict]:
        """Extract imports from Java AST"""
        # Placeholder implementation
        return []
        
    def get_variables(self, ast_node: Dict) -> List[Dict]:
        """Extract variables from Java AST"""
        # Placeholder implementation
        return []

class CppAnalyzer(LanguageAnalyzer):
    """C++ source code analyzer"""
    
    def __init__(self):
        super().__init__()
        self.file_extensions = [".cpp", ".hpp", ".cc", ".hh"]
        
    def parse_file(self, filename: str) -> Dict:
        """Parse C++ source file using external parser"""
        # Use clang or similar tool
        # This is a placeholder implementation
        return {}
        
    def get_functions(self, ast_node: Dict) -> List[Dict]:
        """Extract functions from C++ AST"""
        # Placeholder implementation
        return []
        
    def get_classes(self, ast_node: Dict) -> List[Dict]:
        """Extract classes from C++ AST"""
        # Placeholder implementation
        return []
        
    def get_imports(self, ast_node: Dict) -> List[Dict]:
        """Extract includes from C++ AST"""
        # Placeholder implementation
        return []
        
    def get_variables(self, ast_node: Dict) -> List[Dict]:
        """Extract variables from C++ AST"""
        # Placeholder implementation
        return []

class GoAnalyzer(LanguageAnalyzer):
    """Go source code analyzer"""
    
    def __init__(self):
        super().__init__()
        self.file_extensions = [".go"]
        
    def parse_file(self, filename: str) -> Dict:
        """Parse Go source file using external parser"""
        # Use go/parser or similar tool
        # This is a placeholder implementation
        return {}
        
    def get_functions(self, ast_node: Dict) -> List[Dict]:
        """Extract functions from Go AST"""
        # Placeholder implementation
        return []
        
    def get_classes(self, ast_node: Dict) -> List[Dict]:
        """Extract types from Go AST"""
        # Placeholder implementation
        return []
        
    def get_imports(self, ast_node: Dict) -> List[Dict]:
        """Extract imports from Go AST"""
        # Placeholder implementation
        return []
        
    def get_variables(self, ast_node: Dict) -> List[Dict]:
        """Extract variables from Go AST"""
        # Placeholder implementation
        return []

class JavaScriptAnalyzer(LanguageAnalyzer):
    """JavaScript source code analyzer"""
    
    def __init__(self):
        super().__init__()
        self.file_extensions = [".js", ".jsx", ".ts", ".tsx"]
        
    def parse_file(self, filename: str) -> Dict:
        """Parse JavaScript source file using external parser"""
        # Use esprima or similar tool
        # This is a placeholder implementation
        return {}
        
    def get_functions(self, ast_node: Dict) -> List[Dict]:
        """Extract functions from JavaScript AST"""
        # Placeholder implementation
        return []
        
    def get_classes(self, ast_node: Dict) -> List[Dict]:
        """Extract classes from JavaScript AST"""
        # Placeholder implementation
        return []
        
    def get_imports(self, ast_node: Dict) -> List[Dict]:
        """Extract imports from JavaScript AST"""
        # Placeholder implementation
        return []
        
    def get_variables(self, ast_node: Dict) -> List[Dict]:
        """Extract variables from JavaScript AST"""
        # Placeholder implementation
        return []

class LanguageAnalyzerFactory:
    """Factory for creating language analyzers"""
    
    _analyzers: Dict[str, LanguageAnalyzer] = {
        "python": PythonAnalyzer(),
        "java": JavaAnalyzer(),
        "cpp": CppAnalyzer(),
        "go": GoAnalyzer(),
        "javascript": JavaScriptAnalyzer()
    }
    
    @classmethod
    def get_analyzer(cls, filename: str) -> Optional[LanguageAnalyzer]:
        """Get appropriate analyzer for file"""
        ext = os.path.splitext(filename)[1].lower()
        for analyzer in cls._analyzers.values():
            if analyzer.supports_file(filename):
                return analyzer
        return None
        
    @classmethod
    def register_analyzer(cls, language: str, analyzer: LanguageAnalyzer):
        """Register new language analyzer"""
        cls._analyzers[language] = analyzer 