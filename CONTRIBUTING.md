# 贡献指南

感谢您对Re-movery项目的关注！我们欢迎任何形式的贡献，包括但不限于：

- 报告问题
- 提交功能建议
- 改进文档
- 提交代码修复
- 添加新功能

## 开发环境设置

1. 安装Go 1.21或更高版本
2. 克隆仓库：
   ```bash
   git clone https://github.com/heyangxu/Re-movery.git
   cd Re-movery
   ```
3. 安装依赖：
   ```bash
   cd go
   go mod download
   ```
4. 安装开发工具：
   ```bash
   # 安装golangci-lint
   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
   ```

## 开发流程

1. 创建新分支：
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. 进行开发，确保：
   - 遵循Go代码规范
   - 添加适当的测试
   - 更新相关文档

3. 运行测试：
   ```bash
   make test
   ```

4. 运行代码检查：
   ```bash
   make lint
   ```

5. 提交代码：
   ```bash
   git add .
   git commit -m "feat: Add your feature description"
   ```

6. 推送到GitHub：
   ```bash
   git push origin feature/your-feature-name
   ```

7. 创建Pull Request

## 提交规范

我们使用[Conventional Commits](https://www.conventionalcommits.org/)规范，提交信息格式如下：

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

类型（type）包括：
- feat: 新功能
- fix: 修复
- docs: 文档更新
- style: 代码格式（不影响代码运行的变动）
- refactor: 重构
- perf: 性能优化
- test: 测试
- chore: 构建过程或辅助工具的变动

## 代码规范

- 遵循[Go代码规范](https://golang.org/doc/effective_go)
- 使用`gofmt`格式化代码
- 添加适当的注释
- 保持代码简洁明了
- 使用有意义的变量和函数名

## 测试规范

- 为新功能添加单元测试
- 确保测试覆盖率不降低
- 测试应该简单明了
- 避免测试之间的依赖

## 文档规范

- 保持README.md的更新
- 为新功能添加文档
- 更新API文档
- 添加示例代码

## 问题反馈

如果您发现了问题或有新的想法，请：

1. 检查是否已存在相关的Issue
2. 如果没有，创建新的Issue
3. 清晰描述问题或建议
4. 提供复现步骤（如果适用）
5. 提供相关的日志或截图（如果适用）

## 行为准则

请参阅我们的[行为准则](CODE_OF_CONDUCT.md)。

## 许可证

通过提交代码，您同意您的代码遵循项目的[MIT许可证](LICENSE)。 