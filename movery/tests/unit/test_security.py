import unittest
import os
import tempfile
import shutil
import time
import threading
from movery.utils.security import SecurityChecker

class TestSecurityChecker(unittest.TestCase):
    def setUp(self):
        """测试前的准备工作"""
        self.checker = SecurityChecker()
        self.test_dir = tempfile.mkdtemp()
        
        # 创建测试代码文件
        self.test_code = '''
import os
import sys
import time
import random
import socket
import subprocess

def unsafe_memory():
    # 大量内存分配
    large_list = [i for i in range(10**7)]
    return large_list

def unsafe_execution():
    # 长时间执行
    time.sleep(5)
    return "Done"

def unsafe_file_access():
    # 危险的文件操作
    with open("/etc/passwd", "r") as f:
        data = f.read()
    return data

def unsafe_network():
    # 未经验证的网络连接
    sock = socket.socket()
    sock.connect(("example.com", 80))
    return sock

def unsafe_input():
    # 未验证的输入
    user_input = input("Enter command: ")
    os.system(user_input)

def unsafe_random():
    # 不安全的随机数生成
    return random.randint(1, 100)

def unsafe_sensitive_data():
    # 敏感数据暴露
    password = "super_secret_123"
    print(f"Password is: {password}")

def unsafe_sandbox():
    # 沙箱逃逸尝试
    subprocess.call("rm -rf /", shell=True)
'''
        self.test_file = os.path.join(self.test_dir, "test_code.py")
        with open(self.test_file, "w") as f:
            f.write(self.test_code)

    def tearDown(self):
        """测试后的清理工作"""
        shutil.rmtree(self.test_dir)

    def test_check_memory_usage(self):
        """测试内存使用检查"""
        result = self.checker.check_memory_usage(self.test_file)
        self.assertTrue(result["has_issues"])
        self.assertIn("large_list", result["details"])
        self.assertGreater(len(result["patterns"]), 0)

    def test_check_execution_time(self):
        """测试执行时间检查"""
        result = self.checker.check_execution_time(self.test_file)
        self.assertTrue(result["has_issues"])
        self.assertIn("time.sleep", result["details"])
        self.assertGreater(len(result["patterns"]), 0)

    def test_check_file_access(self):
        """测试文件访问检查"""
        result = self.checker.check_file_access(self.test_file)
        self.assertTrue(result["has_issues"])
        self.assertIn("/etc/passwd", result["details"])
        self.assertGreater(len(result["patterns"]), 0)

    def test_check_network_access(self):
        """测试网络访问检查"""
        result = self.checker.check_network_access(self.test_file)
        self.assertTrue(result["has_issues"])
        self.assertIn("socket.connect", result["details"])
        self.assertGreater(len(result["patterns"]), 0)

    def test_check_input_validation(self):
        """测试输入验证检查"""
        result = self.checker.check_input_validation(self.test_file)
        self.assertTrue(result["has_issues"])
        self.assertIn("os.system", result["details"])
        self.assertGreater(len(result["patterns"]), 0)

    def test_check_random_generation(self):
        """测试随机数生成检查"""
        result = self.checker.check_random_generation(self.test_file)
        self.assertTrue(result["has_issues"])
        self.assertIn("random.randint", result["details"])
        self.assertGreater(len(result["patterns"]), 0)

    def test_check_sensitive_data(self):
        """测试敏感数据检查"""
        result = self.checker.check_sensitive_data(self.test_file)
        self.assertTrue(result["has_issues"])
        self.assertIn("password", result["details"])
        self.assertGreater(len(result["patterns"]), 0)

    def test_check_sandbox_escape(self):
        """测试沙箱逃逸检查"""
        result = self.checker.check_sandbox_escape(self.test_file)
        self.assertTrue(result["has_issues"])
        self.assertIn("subprocess.call", result["details"])
        self.assertGreater(len(result["patterns"]), 0)

    def test_perform_full_check(self):
        """测试完整安全检查"""
        results = self.checker.perform_full_check(self.test_file)
        
        self.assertIsInstance(results, dict)
        self.assertGreater(len(results), 0)
        
        # 验证所有检查项都已执行
        expected_checks = [
            "memory_usage",
            "execution_time",
            "file_access",
            "network_access",
            "input_validation",
            "random_generation",
            "sensitive_data",
            "sandbox_escape"
        ]
        
        for check in expected_checks:
            self.assertIn(check, results)
            self.assertTrue(results[check]["has_issues"])
            self.assertGreater(len(results[check]["patterns"]), 0)

    def test_concurrent_checks(self):
        """测试并发安全检查"""
        # 创建多个测试文件
        test_files = []
        for i in range(5):
            file_path = os.path.join(self.test_dir, f"test_code_{i}.py")
            with open(file_path, "w") as f:
                f.write(self.test_code)
            test_files.append(file_path)
        
        # 并发执行检查
        results = []
        threads = []
        
        def check_file(file_path):
            result = self.checker.perform_full_check(file_path)
            results.append(result)
        
        for file_path in test_files:
            thread = threading.Thread(target=check_file, args=(file_path,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        self.assertEqual(len(results), len(test_files))
        for result in results:
            self.assertIsInstance(result, dict)
            self.assertGreater(len(result), 0)

if __name__ == '__main__':
    unittest.main() 