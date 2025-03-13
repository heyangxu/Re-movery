# Re-Movery

Re-Movery是一个基于Movery重构的漏洞代码克隆检测工具。该版本使用Go语言重新实现，在原有功能基础上进行了重大改进，提升了性能并增加了新特性。

Re-Movery主要用于检测代码库中可能存在的已知漏洞代码克隆。它不仅可以发现完全相同的代码克隆，还能识别经过修改的漏洞代码，帮助开发者及时发现和修复潜在的安全问题。

## 快速开始

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

5. 查看报告:
扫描完成后，在`reports`目录下会生成HTML格式的分析报告。

## 命令行参数

- `-config`: 配置文件路径 (默认: config.json)
- `-target`: 目标扫描目录或文件 (默认: .)
- `-output`: 报告输出目录 (默认: reports)
- `-verbose`: 启用详细日志 (默认: false)
- `-memory`: 最大内存使用量(GB) (默认: 8.0)

## 主要特性

### 高性能处理
- Go语言实现，性能优异
- 并发处理
- 内存使用监控
- 工作池调度
- 结果缓存机制

### 高级分析
- 基于模式的检测
- AST语法分析
- 语义相似度匹配
- 上下文感知检测

### 多语言支持
- Go (主要支持)
- 其他语言支持陆续添加中

### 全面的报告
- HTML格式报告
- 可视化图表
- 漏洞严重程度分类
- 详细的上下文信息
- 修复建议

### 安全特性
- 输入验证
- 资源限制
- 内存使用监控

## 项目结构
```
re-movery/
  ├── go/                    # Go实现
  │   ├── cmd/              # 命令行工具
  │   │   └── movery/       # 主程序
  │   ├── internal/         # 内部包
  │   │   ├── config/       # 配置管理
  │   │   ├── utils/        # 工具函数
  │   │   ├── analyzers/    # 代码分析器
  │   │   ├── detectors/    # 漏洞检测器
  │   │   └── reporters/    # 报告生成器
  │   ├── pkg/              # 公共包
  │   │   └── types/        # 类型定义
  │   └── web/              # Web相关
  │       └── templates/    # HTML模板
  └── docs/                 # 文档
```

## 配置说明

### 配置文件

创建`config.json`文件来自定义Re-Movery的行为:

```json
{
    "processing": {
        "num_workers": 4,        # 工作协程数
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

## 贡献

欢迎提交Pull Request！请查看[CONTRIBUTING.md](CONTRIBUTING.md)了解如何参与项目开发。

## 许可证

本项目采用MIT许可证 - 详见[LICENSE](LICENSE)文件。

## 关于

本项目由[heyangxu](https://github.com/heyangxu)开发和维护。

如需报告问题，请在[GitHub仓库](https://github.com/heyangxu/Re-movery)提交Issue。
