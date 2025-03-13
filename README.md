# Re-Movery

Re-Movery是一个基于Movery重构的漏洞代码克隆检测工具，该版本在原有功能基础上进行了重大改进,提升了性能并增加了新特性。提供Python和Go两个版本的改进。该工具主要用于检测代码库中可能存在的已知漏洞代码克隆。它不仅可以发现完全相同的代码克隆，还能识别经过修改的漏洞代码，帮助开发者及时发现和修复潜在的安全问题。

## 版本说明

本项目提供两个版本的实现：
- **Python版本**：原始实现，功能完整，易于扩展
- **Go版本**：新增实现，性能优化，并发处理

## Python版本

### 安装

1. 安装依赖:
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

### Python版本特性

- 多进程并行分析
- 内存映射文件处理
- 结果缓存机制
- 算法优化
- 支持多种编程语言：
  - Python
  - Java
  - C/C++
  - JavaScript/TypeScript

## Go版本

### 安装

1. 安装Go (1.21或更高版本)

2. 克隆仓库:
```bash
git clone https://github.com/heyangxu/Re-movery.git
cd Re-movery
```

3. 构建项目:
```bash
cd go
go build -o movery ./cmd/movery
```

4. 运行扫描:
```bash
./movery -config config.json -target /path/to/your/code -output reports -memory 8.0
```

### Go版本特性

- Go语言实现，性能优异
- 并发处理
- 内存使用监控
- 工作池调度
- 结果缓存机制
- 当前主要支持Go语言，其他语言支持陆续添加中

### Go版本命令行参数

- `-config`: 配置文件路径 (默认: config.json)
- `-target`: 目标扫描目录或文件 (默认: .)
- `-output`: 报告输出目录 (默认: reports)
- `-verbose`: 启用详细日志 (默认: false)
- `-memory`: 最大内存使用量(GB) (默认: 8.0)

## 共同特性

### 高级分析
- 基于模式的检测
- AST语法分析
- 语义相似度匹配
- 上下文感知检测

### 全面的报告
- HTML格式报告
- 可视化图表
- 漏洞严重程度分类
- 详细的上下文信息
- 修复建议

### 安全特性
- 输入验证
- 资源限制
- 速率限制

## 项目结构
```
re-movery/
  ├── movery/           # Python实现
  │   ├── config/       # 配置
  │   ├── utils/        # 工具
  │   ├── analyzers/    # 分析器
  │   ├── detectors/    # 检测器
  │   └── reporters/    # 报告生成器
  │
  ├── go/               # Go实现
  │   ├── cmd/         # 命令行工具
  │   │   └── movery/  # 主程序
  │   ├── internal/    # 内部包
  │   │   ├── config/  # 配置管理
  │   │   ├── utils/   # 工具函数
  │   │   ├── analyzers/# 代码分析器
  │   │   ├── detectors/# 漏洞检测器
  │   │   └── reporters/# 报告生成器
  │   ├── pkg/         # 公共包
  │   │   └── types/   # 类型定义
  │   └── web/         # Web相关
  │       └── templates/# HTML模板
  │
  └── docs/            # 文档
```

## 配置说明

### 配置文件

两个版本都使用`config.json`进行配置，示例如下:

```json
{
    "processing": {
        "num_workers": 4,        # 工作进程/协程数
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

## 版本选择建议

- 如果您需要分析多种编程语言的代码，建议使用Python版本
- 如果您主要分析Go语言代码，或对性能有较高要求，建议使用Go版本
- 两个版本的检测结果是兼容的，可以根据需要混合使用

## 贡献

欢迎提交Pull Request！请查看[CONTRIBUTING.md](CONTRIBUTING.md)了解如何参与项目开发。

## 许可证

本项目采用MIT许可证 - 详见[LICENSE](LICENSE)文件。

## 关于

本项目由[heyangxu](https://github.com/heyangxu)开发和维护。

如需报告问题，请在[GitHub仓库](https://github.com/heyangxu/Re-movery)提交Issue。
