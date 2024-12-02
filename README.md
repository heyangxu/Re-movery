# Re-Movery

Re-Movery是一个基于Movery重构的漏洞代码克隆检测工具。该版本在原有功能基础上进行了重大改进,提升了性能并增加了新特性。

Re-Movery主要用于检测代码库中可能存在的已知漏洞代码克隆。它不仅可以发现完全相同的代码克隆,还能识别经过修改的漏洞代码,帮助开发者及时发现和修复潜在的安全问题。

## 快速开始

1. 安装Re-Movery:

```bash
pip install -r requirements.txt
pip install -e .
```

2. 创建配置文件`config.json`:

```json
{
    "processing": {
        "num_processes": 4,
        "enable_cache": true
    }
}
```

3. 运行扫描:

```bash
movery /path/to/your/code
```

4. 查看报告:
扫描完成后,在`reports`目录下会生成HTML格式的分析报告。

## 主要特性

### 高性能处理
- 多进程并行分析
- 内存映射文件处理
- 结果缓存机制
- 算法优化

### 高级分析
- 基于模式的检测
- AST语法分析
- 语义相似度匹配
- 上下文感知检测

### 多语言支持
- Python
- Java
- C/C++
- Go
- JavaScript/TypeScript

### 全面的报告
- HTML格式报告
- 可视化图表
- 漏洞严重程度分类
- 详细的上下文信息
- 修复建议

### 安全特性
- 输入验证
- 资源限制
- 沙箱执行
- 速率限制

## 项目结构
```
re-movery/
  ├── config/           # 配置
  ├── utils/            # 工具
  │   ├── logging.py    # 日志
  │   ├── memory.py     # 内存管理
  │   └── parallel.py   # 并行处理
  ├── analyzers/        # 分析器
  │   └── language.py   # 语言分析
  ├── detectors/        # 检测器
  │   └── vulnerability.py  # 漏洞检测
  └── reporters/        # 报告生成器
      └── html.py       # HTML报告
```

## 配置说明

### 配置文件

创建`config.json`文件来自定义Re-Movery的行为:

```json
{
    "processing": {
        "num_processes": 4,      # 并行进程数
        "enable_cache": true     # 启用缓存
    },
    "detector": {
        "min_similarity": 0.8,   # 最小相似度
        "enable_semantic_match": true  # 启用语义匹配
    }
}
```

### 漏洞签名

创建`signatures.json`文件来定义漏洞模式:

```json
{
    "signatures": [
        {
            "id": "CWE-78",
            "name": "OS命令注入",
            "severity": "严重",
            "code_patterns": [
                "os\\.system\\(.*\\)"
            ]
        }
    ]
}
```

## 许可证

本项目采用MIT许可证 - 详见[LICENSE](LICENSE)文件。

## 关于

本项目由[heyangxu](https://github.com/heyangxu)开发和维护。

如需报告问题,请在[GitHub仓库](https://github.com/heyangxu/Re-movery)提交Issue。
