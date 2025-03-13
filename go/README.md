# Re-movery (Go版本)

Re-movery是一个强大的安全漏洞扫描工具，用于检测代码中的潜在安全问题。Go版本提供了高性能的扫描能力和多种接口选项。

## 功能特点

- 支持多种编程语言（目前支持Python和JavaScript）
- 提供命令行、Web界面和API接口
- 生成HTML、JSON和XML格式的报告
- 支持并行扫描和增量扫描
- 与CI/CD工具集成（GitHub Actions、GitLab CI）
- VS Code扩展支持

## 安装

### 从源码安装

```bash
git clone https://github.com/re-movery/re-movery.git
cd re-movery/go
go install ./cmd/movery
```

### 使用Go工具安装

```bash
go install github.com/re-movery/re-movery/cmd/movery@latest
```

## 使用方法

### 命令行扫描

```bash
# 扫描单个文件
movery scan --file path/to/file.py

# 扫描目录
movery scan --dir path/to/directory

# 排除特定文件或目录
movery scan --dir path/to/directory --exclude "node_modules,*.min.js"

# 生成HTML报告
movery scan --dir path/to/directory --output report.html

# 启用并行处理
movery scan --dir path/to/directory --parallel

# 启用增量扫描
movery scan --dir path/to/directory --incremental
```

### 启动Web界面

```bash
# 默认配置（localhost:8080）
movery web

# 自定义主机和端口
movery web --host 0.0.0.0 --port 8080

# 启用调试模式
movery web --debug
```

### 启动API服务器

```bash
# 默认配置（localhost:8081）
movery server

# 自定义主机和端口
movery server --host 0.0.0.0 --port 8081

# 启用调试模式
movery server --debug
```

### 生成集成文件

```bash
# 生成GitHub Actions工作流文件
movery generate github-action

# 生成GitLab CI配置文件
movery generate gitlab-ci

# 生成VS Code扩展配置文件
movery generate vscode-extension
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

## 配置

Re-movery可以通过命令行参数或配置文件进行配置。配置文件支持YAML、JSON和TOML格式。

```yaml
# re-movery.yaml
scanner:
  parallel: true
  incremental: true
  confidenceThreshold: 0.7

web:
  host: localhost
  port: 8080
  debug: false

server:
  host: localhost
  port: 8081
  debug: false
```

## 开发

### 构建

```bash
cd go
go build -o movery ./cmd/movery
```

### 测试

```bash
go test ./...
```

### 贡献

欢迎提交Pull Request和Issue。请确保您的代码符合Go的代码规范，并通过所有测试。

## 许可证

MIT 