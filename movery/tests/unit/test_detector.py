import unittest
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from movery.detectors.vulnerability import VulnerabilityDetector

class TestVulnerabilityDetector(unittest.TestCase):
    def setUp(self):
        self.detector = VulnerabilityDetector()
        self.test_data_dir = os.path.join(os.path.dirname(__file__), 'test_data')
        if not os.path.exists(self.test_data_dir):
            os.makedirs(self.test_data_dir)

    def test_load_signatures(self):
        """测试加载漏洞签名"""
        # 创建测试签名文件
        test_sig_file = os.path.join(self.test_data_dir, 'test_signatures.json')
        with open(test_sig_file, 'w') as f:
            f.write('''
            {
                "signatures": [
                    {
                        "id": "CWE-78",
                        "name": "OS Command Injection",
                        "severity": "HIGH",
                        "code_patterns": ["os\\.system\\(.*\\)"]
                    }
                ]
            }
            ''')
        
        self.detector.load_signatures(test_sig_file)
        self.assertEqual(len(self.detector.signatures), 1)
        self.assertEqual(self.detector.signatures[0].id, "CWE-78")

    def test_detect_vulnerability(self):
        """测试漏洞检测"""
        # 创建测试代码文件
        test_code_file = os.path.join(self.test_data_dir, 'test_code.py')
        with open(test_code_file, 'w') as f:
            f.write('''
            import os
            def unsafe_function(cmd):
                os.system(cmd)  # 不安全的系统命令执行
            ''')

        matches = self.detector.detect_file(test_code_file)
        self.assertTrue(len(matches) > 0)
        self.assertEqual(matches[0].signature.id, "CWE-78")

    def test_false_positive(self):
        """测试误报情况"""
        # 创建安全的测试代码
        test_safe_file = os.path.join(self.test_data_dir, 'test_safe.py')
        with open(test_safe_file, 'w') as f:
            f.write('''
            def safe_function():
                print("This is safe code")
            ''')

        matches = self.detector.detect_file(test_safe_file)
        self.assertEqual(len(matches), 0)

    def test_similarity_matching(self):
        """测试相似度匹配"""
        # 创建相似代码测试文件
        test_similar_file = os.path.join(self.test_data_dir, 'test_similar.py')
        with open(test_similar_file, 'w') as f:
            f.write('''
            import subprocess
            def similar_unsafe(command):
                subprocess.call(command, shell=True)  # 类似的不安全模式
            ''')

        matches = self.detector.detect_file(test_similar_file)
        self.assertTrue(len(matches) > 0)
        self.assertTrue(matches[0].confidence > 0.7)

    def tearDown(self):
        """清理测试数据"""
        import shutil
        if os.path.exists(self.test_data_dir):
            shutil.rmtree(self.test_data_dir)

if __name__ == '__main__':
    unittest.main() 