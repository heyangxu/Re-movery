import unittest
import os
import sys
import tempfile
import shutil
import subprocess
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from movery.detectors.vulnerability import VulnerabilityDetector
from movery.utils.security import SecurityChecker

class TestSecurity(unittest.TestCase):
    def setUp(self):
        """设置测试环境"""
        self.test_dir = tempfile.mkdtemp()
        self.security_checker = SecurityChecker()
        self.detector = VulnerabilityDetector()

    def create_test_file(self, content):
        """创建测试文件"""
        file_path = os.path.join(self.test_dir, 'test_file.py')
        with open(file_path, 'w') as f:
            f.write(content)
        return file_path

    def test_memory_limit(self):
        """测试内存限制"""
        # 创建一个可能导致内存溢出的文件
        test_file = self.create_test_file('''
        def memory_intensive():
            large_list = [i for i in range(10**8)]  # 尝试创建大列表
            return large_list
        ''')

        # 检查内存使用
        memory_usage = self.security_checker.check_memory_usage(test_file)
        self.assertLess(memory_usage, 8 * 1024 * 1024 * 1024)  # 8GB限制

    def test_execution_timeout(self):
        """测试执行超时"""
        # 创建一个可能导致无限循环的文件
        test_file = self.create_test_file('''
        def infinite_loop():
            while True:
                pass
        ''')

        # 检查执行时间
        with self.assertRaises(TimeoutError):
            self.security_checker.check_execution_time(test_file, timeout=5)

    def test_file_access(self):
        """测试文件访问限制"""
        # 创建测试文件
        test_file = self.create_test_file('''
        import os

        def access_sensitive_file():
            with open('/etc/passwd', 'r') as f:
                return f.read()
        ''')

        # 检查文件访问
        violations = self.security_checker.check_file_access(test_file)
        self.assertTrue(len(violations) > 0)
        self.assertIn('/etc/passwd', violations[0])

    def test_network_access(self):
        """测试网络访问限制"""
        # 创建测试文件
        test_file = self.create_test_file('''
        import socket

        def connect_external():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('example.com', 80))
        ''')

        # 检查网络访问
        violations = self.security_checker.check_network_access(test_file)
        self.assertTrue(len(violations) > 0)
        self.assertIn('socket.connect', violations[0])

    def test_code_injection(self):
        """测试代码注入防护"""
        # 创建测试文件
        test_file = self.create_test_file('''
        def execute_input(user_input):
            exec(user_input)  # 危险的代码执行
        ''')

        # 检查代码注入
        vulnerabilities = self.detector.detect_file(test_file)
        self.assertTrue(len(vulnerabilities) > 0)
        self.assertEqual(vulnerabilities[0].severity, 'HIGH')

    def test_input_validation(self):
        """测试输入验证"""
        # 创建测试文件
        test_file = self.create_test_file('''
        def process_input(user_input):
            # 没有验证的输入处理
            return eval(user_input)
        ''')

        # 检查输入验证
        issues = self.security_checker.check_input_validation(test_file)
        self.assertTrue(len(issues) > 0)
        self.assertIn('eval', str(issues[0]))

    def test_secure_random(self):
        """测试安全随机数生成"""
        # 创建测试文件
        test_file = self.create_test_file('''
        import random

        def generate_token():
            return ''.join(random.choice('0123456789ABCDEF') for i in range(32))
        ''')

        # 检查随机数生成
        issues = self.security_checker.check_random_generation(test_file)
        self.assertTrue(len(issues) > 0)
        self.assertIn('random.choice', str(issues[0]))

    def test_sensitive_data(self):
        """测试敏感数据处理"""
        # 创建测试文件
        test_file = self.create_test_file('''
        def process_password(password):
            print(f"Password is: {password}")  # 敏感信息泄露
            return hash(password)  # 不安全的哈希
        ''')

        # 检查敏感数据处理
        issues = self.security_checker.check_sensitive_data(test_file)
        self.assertTrue(len(issues) > 0)
        self.assertIn('password', str(issues[0]).lower())

    def test_sandbox_escape(self):
        """测试沙箱逃逸防护"""
        # 创建测试文件
        test_file = self.create_test_file('''
        import subprocess
        import os

        def dangerous_operation():
            os.system('rm -rf /')  # 危险的系统命令
            subprocess.call(['chmod', '777', '/etc/passwd'])  # 危险的权限修改
        ''')

        # 检查沙箱逃逸
        violations = self.security_checker.check_sandbox_escape(test_file)
        self.assertTrue(len(violations) > 0)
        self.assertIn('os.system', str(violations[0]))

    def tearDown(self):
        """清理测试环境"""
        shutil.rmtree(self.test_dir)

if __name__ == '__main__':
    unittest.main() 