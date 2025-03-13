import unittest
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from movery.analyzers.code_analyzer import CodeAnalyzer

class TestCodeAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = CodeAnalyzer()
        self.test_data_dir = os.path.join(os.path.dirname(__file__), 'test_data')
        if not os.path.exists(self.test_data_dir):
            os.makedirs(self.test_data_dir)

    def test_parse_python(self):
        """测试Python代码解析"""
        test_file = os.path.join(self.test_data_dir, 'test_python.py')
        with open(test_file, 'w') as f:
            f.write('''
            def example_function():
                x = 1
                y = 2
                return x + y
            ''')

        ast = self.analyzer.parse_file(test_file)
        self.assertIsNotNone(ast)
        self.assertEqual(ast.type, 'Module')

    def test_analyze_function(self):
        """测试函数分析"""
        test_file = os.path.join(self.test_data_dir, 'test_function.py')
        with open(test_file, 'w') as f:
            f.write('''
            def process_data(data):
                result = []
                for item in data:
                    if item > 0:
                        result.append(item * 2)
                return result
            ''')

        functions = self.analyzer.analyze_functions(test_file)
        self.assertEqual(len(functions), 1)
        self.assertEqual(functions[0].name, 'process_data')
        self.assertTrue(functions[0].has_loop)
        self.assertTrue(functions[0].has_condition)

    def test_data_flow(self):
        """测试数据流分析"""
        test_file = os.path.join(self.test_data_dir, 'test_dataflow.py')
        with open(test_file, 'w') as f:
            f.write('''
            def data_flow_example(user_input):
                data = user_input.strip()
                processed = data.lower()
                return processed
            ''')

        flows = self.analyzer.analyze_data_flow(test_file)
        self.assertTrue(len(flows) > 0)
        self.assertIn('user_input', flows[0].sources)
        self.assertIn('processed', flows[0].sinks)

    def test_complexity_analysis(self):
        """测试复杂度分析"""
        test_file = os.path.join(self.test_data_dir, 'test_complexity.py')
        with open(test_file, 'w') as f:
            f.write('''
            def complex_function(x, y):
                if x > 0:
                    if y > 0:
                        return x + y
                    else:
                        return x - y
                else:
                    if y < 0:
                        return -x - y
                    else:
                        return -x + y
            ''')

        complexity = self.analyzer.analyze_complexity(test_file)
        self.assertTrue(complexity > 1)
        self.assertEqual(complexity, 4)  # 4个条件分支

    def tearDown(self):
        """清理测试数据"""
        import shutil
        if os.path.exists(self.test_data_dir):
            shutil.rmtree(self.test_data_dir)

if __name__ == '__main__':
    unittest.main() 