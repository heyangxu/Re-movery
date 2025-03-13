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
# 扫描单个文件
./movery scan --file path/to/file.py

# 扫描目录
./movery scan --dir path/to/directory

# 排除特定文件或目录
./movery scan --dir path/to/directory --exclude "node_modules,*.min.js"

# 生成HTML报告
./movery scan --dir path/to/directory --output report.html

# 启用并行处理
./movery scan --dir path/to/directory --parallel

# 启用增量扫描
./movery scan --dir path/to/directory --incremental
```

### Go版本特性

- Go语言实现，性能优异
- 并发处理
- 内存使用监控
- 工作池调度
- 结果缓存机制
- 多种接口选项：命令行、Web界面和API接口
- 生成HTML、JSON和XML格式的报告
- 与CI/CD工具集成（GitHub Actions、GitLab CI）
- 当前支持Python和JavaScript语言，其他语言支持陆续添加中

### Go版本命令行参数

- `scan`: 扫描文件或目录
  - `--file`: 指定要扫描的文件
  - `--dir`: 指定要扫描的目录
  - `--exclude`: 排除特定文件或目录（逗号分隔）
  - `--output`: 报告输出路径
  - `--format`: 报告格式（html, json, xml）
  - `--parallel`: 启用并行处理
  - `--incremental`: 启用增量扫描
  - `--confidence`: 置信度阈值（0.0-1.0）

- `web`: 启动Web界面
  - `--host`: 指定主机（默认: localhost）
  - `--port`: 指定端口（默认: 8080）
  - `--debug`: 启用调试模式

- `server`: 启动API服务器
  - `--host`: 指定主机（默认: localhost）
  - `--port`: 指定端口（默认: 8081）
  - `--debug`: 启用调试模式

- `generate`: 生成集成文件
  - `github-action`: 生成GitHub Actions工作流文件
  - `gitlab-ci`: 生成GitLab CI配置文件
  - `vscode-extension`: 生成VS Code扩展配置文件

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
  │   ├── cmd/          # 命令行工具
  │   │   └── movery/   # 主程序
  │   ├── internal/     # 内部包
  │   │   ├── cmd/      # 命令行命令
  │   │   ├── config/   # 配置管理
  │   │   ├── core/     # 核心功能
  │   │   ├── detectors/# 漏洞检测器
  │   │   ├── reporters/# 报告生成器
  │   │   ├── api/      # API服务器
  │   │   └── web/      # Web应用
  │   └── pkg/          # 公共包
  │
  └── docs/             # 文档
```

## 配置说明

### 配置文件

两个版本都支持配置文件，Go版本支持JSON和YAML格式：

```yaml
# re-movery.yaml
scanner:
  parallel: true
  incremental: true
  confidenceThreshold: 0.7
  excludePatterns:
    - node_modules
    - "*.min.js"

web:
  host: localhost
  port: 8080
  debug: false

server:
  host: localhost
  port: 8081
  debug: false
```

### 漏洞签名

创建`signatures.json`文件来定义漏洞模式:

```json
{
    "signatures": [
        {
            "id": "CWE-78",
            "name": "OS命令注入",
            "severity": "high",
            "code_patterns": [
                "os\\.system\\(.*\\)"
            ]
        }
    ]
}
```

## API文档

### 扫描代码

```
POST /api/scan/code
Content-Type: application/json

{
  "code": "代码内容",
  "language": "python",
  "fileName": "example.py"
}
```

### 扫描文件

```
POST /api/scan/file
Content-Type: multipart/form-data

file: [文件内容]
```

### 扫描目录

```
POST /api/scan/directory
Content-Type: application/json

{
  "directory": "/path/to/directory",
  "excludePatterns": ["node_modules", "*.min.js"],
  "parallel": true,
  "incremental": false
}
```

### 获取支持的语言

```
GET /api/languages
```

## 版本选择建议

- 如果您需要分析多种编程语言的代码，建议使用Python版本
- 如果您主要分析Python和JavaScript代码，或对性能有较高要求，建议使用Go版本
- 两个版本的检测结果是兼容的，可以根据需要混合使用

## 贡献

欢迎提交Pull Request！请查看[CONTRIBUTING.md](CONTRIBUTING.md)了解如何参与项目开发。

## 许可证

本项目采用MIT许可证 - 详见[LICENSE](LICENSE)文件。

## 关于

本项目由[heyangxu](https://github.com/heyangxu)开发和维护。

如需报告问题，请在[GitHub仓库](https://github.com/heyangxu/Re-movery)提交Issue。
