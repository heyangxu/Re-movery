import os
import ast
import time
import psutil
import socket
import threading
from typing import List, Dict, Any, Optional
import re
import astroid

class SecurityChecker:
    """安全检查器类"""
    
    def __init__(self):
        """初始化安全检查器"""
        self.sensitive_patterns = {
            'file_access': [
                r'open\s*\([^)]*[\'"]\/(?:etc|root|home|usr|var)[^\'"]*[\'"]\s*\)',
                r'os\.(?:remove|unlink|rmdir|mkdir|chmod|chown)',
            ],
            'network_access': [
                r'socket\.(?:socket|connect|bind|listen)',
                r'urllib\.(?:request|urlopen)',
                r'requests\.(?:get|post|put|delete)',
            ],
            'code_execution': [
                r'(?:exec|eval|subprocess\.(?:call|Popen|run))',
                r'os\.(?:system|popen|spawn)',
            ],
            'input_validation': [
                r'input\s*\(',
                r'raw_input\s*\(',
                r'eval\s*\(',
            ],
            'random_generation': [
                r'random\.(?:random|randint|choice|randrange)',
                r'secrets\.(?:token_hex|token_bytes|token_urlsafe)',
            ],
            'sensitive_data': [
                r'(?:password|secret|key|token|credential)',
                r'print\s*\([^)]*(?:password|secret|key|token)[^)]*\)',
            ],
        }

    def check_memory_usage(self, file_path: str) -> Dict[str, Any]:
        """检查文件执行时的内存使用情况

        Args:
            file_path: 待检查的文件路径

        Returns:
            Dict[str, Any]: 检查结果
        """
        try:
            process = psutil.Process()
            initial_memory = process.memory_info().rss
            
            # 在新线程中执行代码以便监控
            def execute_code():
                with open(file_path, 'r') as f:
                    exec(f.read())
                    
            thread = threading.Thread(target=execute_code)
            thread.start()
            thread.join(timeout=5)  # 最多等待5秒
            
            final_memory = process.memory_info().rss
            memory_usage = final_memory - initial_memory
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            patterns = [r'list\s*\(.*\)', r'\[\s*.*\s*for\s.*\]', r'dict\s*\(.*\)']
            matches = []
            for pattern in patterns:
                matches.extend(re.finditer(pattern, content))
            
            return {
                "has_issues": memory_usage > 100 * 1024 * 1024,  # 超过100MB认为有问题
                "issues": [f"内存使用量过大: {memory_usage / 1024 / 1024:.2f}MB"] if memory_usage > 100 * 1024 * 1024 else [],
                "details": {match.group(): match.start() for match in matches},
                "patterns": patterns
            }
        except Exception as e:
            return {
                "has_issues": True,
                "issues": [f"内存检查失败: {str(e)}"],
                "details": {},
                "patterns": []
            }

    def check_execution_time(self, file_path: str, timeout: float = 5.0) -> Dict[str, Any]:
        """检查文件执行时间

        Args:
            file_path: 待检查的文件路径
            timeout: 超时时间(秒)

        Returns:
            Dict[str, Any]: 检查结果
        """
        try:
            start_time = time.time()
            
            def execute_code():
                with open(file_path, 'r') as f:
                    exec(f.read())
                    
            thread = threading.Thread(target=execute_code)
            thread.start()
            thread.join(timeout=timeout)
            
            execution_time = time.time() - start_time
            is_timeout = thread.is_alive()
            
            with open(file_path, 'r') as f:
                content = f.read()
            
            patterns = [r'while\s+True:', r'time\.sleep\s*\(', r'for\s+.*\s+in\s+range\s*\(\s*\d+\s*\)']
            matches = []
            for pattern in patterns:
                matches.extend(re.finditer(pattern, content))
            
            return {
                "has_issues": is_timeout or execution_time > timeout,
                "issues": [f"执行超时(>{timeout}秒)"] if is_timeout else [f"执行时间过长: {execution_time:.2f}秒"] if execution_time > timeout else [],
                "details": {match.group(): match.start() for match in matches},
                "patterns": patterns
            }
        except Exception as e:
            return {
                "has_issues": True,
                "issues": [f"执行时间检查失败: {str(e)}"],
                "details": {},
                "patterns": []
            }

    def check_file_access(self, file_path: str) -> Dict[str, Any]:
        """检查文件访问安全性

        Args:
            file_path: 待检查的文件路径

        Returns:
            Dict[str, Any]: 检查结果
        """
        try:
            violations = []
            matches_dict = {}
            with open(file_path, 'r') as f:
                content = f.read()
                
            for pattern in self.sensitive_patterns['file_access']:
                matches = list(re.finditer(pattern, content))
                for match in matches:
                    violations.append(f"发现敏感文件操作: {match.group()}")
                    matches_dict[match.group()] = match.start()
                    
            return {
                "has_issues": len(violations) > 0,
                "issues": violations,
                "details": matches_dict,
                "patterns": self.sensitive_patterns['file_access']
            }
        except Exception as e:
            return {
                "has_issues": True,
                "issues": [f"文件访问检查失败: {str(e)}"],
                "details": {},
                "patterns": []
            }

    def check_network_access(self, file_path: str) -> Dict[str, Any]:
        """检查网络访问安全性

        Args:
            file_path: 待检查的文件路径

        Returns:
            Dict[str, Any]: 检查结果
        """
        try:
            violations = []
            matches_dict = {}
            with open(file_path, 'r') as f:
                content = f.read()
                
            for pattern in self.sensitive_patterns['network_access']:
                matches = list(re.finditer(pattern, content))
                for match in matches:
                    violations.append(f"发现敏感网络操作: {match.group()}")
                    matches_dict[match.group()] = match.start()
                    
            return {
                "has_issues": len(violations) > 0,
                "issues": violations,
                "details": matches_dict,
                "patterns": self.sensitive_patterns['network_access']
            }
        except Exception as e:
            return {
                "has_issues": True,
                "issues": [f"网络访问检查失败: {str(e)}"],
                "details": {},
                "patterns": []
            }

    def check_input_validation(self, file_path: str) -> Dict[str, Any]:
        """检查输入验证

        Args:
            file_path: 待检查的文件路径

        Returns:
            Dict[str, Any]: 检查结果
        """
        try:
            issues = []
            matches_dict = {}
            with open(file_path, 'r') as f:
                content = f.read()
                
            try:
                module = ast.parse(content)
                for node in ast.walk(module):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            func_name = node.func.id
                            if func_name in ['input', 'raw_input']:
                                issues.append(f"未验证的输入: 第{node.lineno}行")
                                matches_dict[func_name] = node.lineno
                        elif isinstance(node.func, ast.Attribute):
                            if node.func.attr in ['get', 'post', 'put', 'delete']:
                                issues.append(f"未验证的HTTP请求: 第{node.lineno}行")
                                matches_dict[f"{node.func.value.id}.{node.func.attr}"] = node.lineno
            except:
                issues.append("代码解析失败")
                
            return {
                "has_issues": len(issues) > 0,
                "issues": issues,
                "details": matches_dict,
                "patterns": self.sensitive_patterns['input_validation']
            }
        except Exception as e:
            return {
                "has_issues": True,
                "issues": [f"输入验证检查失败: {str(e)}"],
                "details": {},
                "patterns": []
            }

    def check_random_generation(self, file_path: str) -> Dict[str, Any]:
        """检查随机数生成安全性

        Args:
            file_path: 待检查的文件路径

        Returns:
            Dict[str, Any]: 检查结果
        """
        try:
            issues = []
            matches_dict = {}
            with open(file_path, 'r') as f:
                content = f.read()
                
            for pattern in self.sensitive_patterns['random_generation']:
                matches = list(re.finditer(pattern, content))
                for match in matches:
                    if 'secrets' not in match.group():
                        issues.append(f"不安全的随机数生成: {match.group()}")
                        matches_dict[match.group()] = match.start()
                    
            return {
                "has_issues": len(issues) > 0,
                "issues": issues,
                "details": matches_dict,
                "patterns": self.sensitive_patterns['random_generation']
            }
        except Exception as e:
            return {
                "has_issues": True,
                "issues": [f"随机数生成检查失败: {str(e)}"],
                "details": {},
                "patterns": []
            }

    def check_sensitive_data(self, file_path: str) -> Dict[str, Any]:
        """检查敏感数据处理

        Args:
            file_path: 待检查的文件路径

        Returns:
            Dict[str, Any]: 检查结果
        """
        try:
            issues = []
            matches_dict = {}
            with open(file_path, 'r') as f:
                content = f.read()
                
            for pattern in self.sensitive_patterns['sensitive_data']:
                matches = list(re.finditer(pattern, content))
                for match in matches:
                    issues.append(f"敏感数据泄露风险: {match.group()}")
                    matches_dict[match.group()] = match.start()
                    
            return {
                "has_issues": len(issues) > 0,
                "issues": issues,
                "details": matches_dict,
                "patterns": self.sensitive_patterns['sensitive_data']
            }
        except Exception as e:
            return {
                "has_issues": True,
                "issues": [f"敏感数据检查失败: {str(e)}"],
                "details": {},
                "patterns": []
            }

    def check_sandbox_escape(self, file_path: str) -> Dict[str, Any]:
        """检查沙箱逃逸

        Args:
            file_path: 待检查的文件路径

        Returns:
            Dict[str, Any]: 检查结果
        """
        try:
            violations = []
            matches_dict = {}
            with open(file_path, 'r') as f:
                content = f.read()
                
            try:
                module = astroid.parse(content)
                for node in module.nodes_of_class(astroid.Call):
                    if isinstance(node.func, astroid.Attribute):
                        if node.func.attrname in ['system', 'popen', 'spawn', 'call', 'Popen', 'run']:
                            violations.append(f"危险的系统调用: {node.as_string()}")
                            matches_dict[node.as_string()] = node.lineno
                    elif isinstance(node.func, astroid.Name):
                        if node.func.name in ['exec', 'eval']:
                            violations.append(f"危险的代码执行: {node.as_string()}")
                            matches_dict[node.as_string()] = node.lineno
            except:
                violations.append("代码解析失败")
                
            return {
                "has_issues": len(violations) > 0,
                "issues": violations,
                "details": matches_dict,
                "patterns": self.sensitive_patterns['code_execution']
            }
        except Exception as e:
            return {
                "has_issues": True,
                "issues": [f"沙箱逃逸检查失败: {str(e)}"],
                "details": {},
                "patterns": []
            }

    def perform_full_check(self, file_path: str) -> Dict[str, Any]:
        """执行完整的安全检查

        Args:
            file_path: 待检查的文件路径

        Returns:
            Dict[str, Any]: 检查结果
        """
        results = {
            'memory_usage': self.check_memory_usage(file_path),
            'execution_time': self.check_execution_time(file_path),
            'file_access': self.check_file_access(file_path),
            'network_access': self.check_network_access(file_path),
            'input_validation': self.check_input_validation(file_path),
            'random_generation': self.check_random_generation(file_path),
            'sensitive_data': self.check_sensitive_data(file_path),
            'sandbox_escape': self.check_sandbox_escape(file_path)
        }
        
        return results
