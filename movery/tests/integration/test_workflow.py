import unittest
import os
import json
import tempfile
import shutil
import time
from movery.detectors.vulnerability import VulnerabilityDetector
from movery.utils.security import SecurityChecker
from movery.analyzers.code_analyzer import CodeAnalyzer
from movery.reporters.html import HTMLReporter

class TestWorkflow(unittest.TestCase):
    def setUp(self):
        """测试前的准备工作"""
        self.test_dir = tempfile.mkdtemp()
        self.create_test_project()
        
        # 初始化组件
        self.detector = VulnerabilityDetector()
        self.checker = SecurityChecker()
        self.analyzer = CodeAnalyzer()
        self.reporter = HTMLReporter()

    def create_test_project(self):
        """创建测试项目结构"""
        # 创建配置文件
        config = {
            "project_name": "Test Project",
            "scan_paths": ["src"],
            "exclude_paths": ["tests", "docs"],
            "report_format": "html",
            "report_path": "reports",
            "severity_threshold": "medium",
            "parallel_processing": True,
            "max_workers": 4
        }
        
        config_file = os.path.join(self.test_dir, "config.json")
        with open(config_file, "w") as f:
            json.dump(config, f, indent=4)
        
        # 创建签名文件
        signatures = {
            "signatures": [
                {
                    "id": "CMD001",
                    "name": "命令注入",
                    "severity": "high",
                    "code_patterns": [
                        "os\\.system\\([^)]*\\)",
                        "subprocess\\.call\\([^)]*\\)"
                    ]
                },
                {
                    "id": "SQL001",
                    "name": "SQL注入",
                    "severity": "high",
                    "code_patterns": [
                        "execute\\(['\"][^'\"]*%[^'\"]*['\"]\\)",
                        "executemany\\(['\"][^'\"]*%[^'\"]*['\"]\\)"
                    ]
                }
            ]
        }
        
        signatures_file = os.path.join(self.test_dir, "signatures.json")
        with open(signatures_file, "w") as f:
            json.dump(signatures, f, indent=4)
        
        # 创建源代码目录
        src_dir = os.path.join(self.test_dir, "src")
        os.makedirs(src_dir)
        
        # 创建测试源代码文件
        vulnerable_code = '''
import os
import subprocess
import sqlite3

def process_command(cmd):
    # 命令注入漏洞
    os.system(cmd)
    subprocess.call(cmd, shell=True)

def query_database(user_id):
    # SQL注入漏洞
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    return cursor.fetchall()

def unsafe_file_operations():
    # 不安全的文件操作
    with open("/etc/passwd", "r") as f:
        data = f.read()
    return data

def main():
    # 调用不安全的函数
    process_command("ls -l")
    query_database("1 OR 1=1")
    unsafe_file_operations()

if __name__ == "__main__":
    main()
'''
        
        vulnerable_file = os.path.join(src_dir, "vulnerable.py")
        with open(vulnerable_file, "w") as f:
            f.write(vulnerable_code)
        
        safe_code = '''
import subprocess
import sqlite3

def safe_command(cmd):
    # 安全的命令执行
    allowed_commands = ["ls", "pwd", "echo"]
    if cmd.split()[0] not in allowed_commands:
        raise ValueError("Command not allowed")
    subprocess.run(cmd.split(), check=True)

def safe_query(user_id):
    # 安全的数据库查询
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()

def safe_file_operations():
    # 安全的文件操作
    try:
        with open("data.txt", "r") as f:
            data = f.read()
        return data
    except Exception as e:
        return str(e)

def main():
    # 调用安全的函数
    safe_command("ls -l")
    safe_query(1)
    safe_file_operations()

if __name__ == "__main__":
    main()
'''
        
        safe_file = os.path.join(src_dir, "safe.py")
        with open(safe_file, "w") as f:
            f.write(safe_code)
        
        # 创建报告目录
        report_dir = os.path.join(self.test_dir, "reports")
        os.makedirs(report_dir)

    def tearDown(self):
        """测试后的清理工作"""
        shutil.rmtree(self.test_dir)

    def test_full_workflow(self):
        """测试完整工作流程"""
        # 加载配置
        config_file = os.path.join(self.test_dir, "config.json")
        with open(config_file, "r") as f:
            config = json.load(f)
        
        # 加载签名
        signatures_file = os.path.join(self.test_dir, "signatures.json")
        self.detector.load_signatures(signatures_file)
        
        # 分析源代码文件
        src_dir = os.path.join(self.test_dir, "src")
        vulnerable_file = os.path.join(src_dir, "vulnerable.py")
        safe_file = os.path.join(src_dir, "safe.py")
        
        # 检测漏洞
        vulnerable_matches = self.detector.detect_file(vulnerable_file)
        safe_matches = self.detector.detect_file(safe_file)
        
        self.assertGreater(len(vulnerable_matches), 0)
        self.assertEqual(len(safe_matches), 0)
        
        # 执行安全检查
        vulnerable_security = self.checker.perform_full_check(vulnerable_file)
        safe_security = self.checker.perform_full_check(safe_file)
        
        self.assertTrue(any(result["has_issues"] for result in vulnerable_security.values()))
        self.assertFalse(any(result["has_issues"] for result in safe_security.values()))
        
        # 代码分析
        vulnerable_analysis = self.analyzer.analyze_file(vulnerable_file)
        safe_analysis = self.analyzer.analyze_file(safe_file)
        
        self.assertGreater(vulnerable_analysis["complexity"], safe_analysis["complexity"])
        
        # 生成报告
        report_data = {
            "project_name": config["project_name"],
            "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "files_scanned": [vulnerable_file, safe_file],
            "vulnerability_results": {
                "vulnerable.py": vulnerable_matches,
                "safe.py": safe_matches
            },
            "security_results": {
                "vulnerable.py": vulnerable_security,
                "safe.py": safe_security
            },
            "analysis_results": {
                "vulnerable.py": vulnerable_analysis,
                "safe.py": safe_analysis
            }
        }
        
        report_file = os.path.join(self.test_dir, "reports", "report.html")
        self.reporter.generate_report(report_data, report_file)
        
        self.assertTrue(os.path.exists(report_file))
        self.assertGreater(os.path.getsize(report_file), 0)

    def test_parallel_processing(self):
        """测试并行处理功能"""
        # 创建多个测试文件
        src_dir = os.path.join(self.test_dir, "src")
        test_files = []
        
        for i in range(5):
            file_path = os.path.join(src_dir, f"test_{i}.py")
            with open(file_path, "w") as f:
                f.write("import os\nos.system('ls')\n")
            test_files.append(file_path)
        
        # 串行处理时间
        start_time = time.time()
        for file_path in test_files:
            self.detector.detect_file(file_path)
            self.checker.perform_full_check(file_path)
            self.analyzer.analyze_file(file_path)
        serial_time = time.time() - start_time
        
        # 并行处理时间
        start_time = time.time()
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for file_path in test_files:
                futures.append(executor.submit(self.detector.detect_file, file_path))
                futures.append(executor.submit(self.checker.perform_full_check, file_path))
                futures.append(executor.submit(self.analyzer.analyze_file, file_path))
            concurrent.futures.wait(futures)
        parallel_time = time.time() - start_time
        
        self.assertLess(parallel_time, serial_time)

    def test_error_handling(self):
        """测试错误处理"""
        # 测试无效的配置文件
        invalid_config = os.path.join(self.test_dir, "invalid_config.json")
        with open(invalid_config, "w") as f:
            f.write("invalid json")
        
        with self.assertRaises(json.JSONDecodeError):
            with open(invalid_config, "r") as f:
                json.load(f)
        
        # 测试不存在的源代码文件
        non_existent_file = os.path.join(self.test_dir, "non_existent.py")
        
        with self.assertRaises(FileNotFoundError):
            self.detector.detect_file(non_existent_file)
        
        # 测试无效的源代码
        invalid_code = os.path.join(self.test_dir, "invalid_code.py")
        with open(invalid_code, "w") as f:
            f.write("invalid python code")
        
        with self.assertRaises(SyntaxError):
            self.analyzer.analyze_file(invalid_code)

if __name__ == '__main__':
    unittest.main() 