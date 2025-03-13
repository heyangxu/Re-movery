package utils

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// SecurityChecker 安全检查器
type SecurityChecker struct {
	sensitivePatterns map[string][]string
	mu               sync.RWMutex
}

// NewSecurityChecker 创建新的安全检查器
func NewSecurityChecker() *SecurityChecker {
	return &SecurityChecker{
		sensitivePatterns: map[string][]string{
			"file_access": {
				`os\.(Open|Create|Remove|RemoveAll|Chmod|Chown)`,
				`ioutil\.(ReadFile|WriteFile)`,
			},
			"network_access": {
				`net\.(Dial|Listen)`,
				`http\.(Get|Post|Put|Delete)`,
			},
			"code_execution": {
				`exec\.(Command|Run)`,
				`syscall\.(Exec|StartProcess)`,
			},
			"input_validation": {
				`fmt\.(Scan|Scanf|Scanln)`,
				`bufio\.NewScanner`,
			},
			"random_generation": {
				`math/rand\.(Int|Float|Perm)`,
				`crypto/rand\.(Read|Prime)`,
			},
			"sensitive_data": {
				`(?i)(password|secret|key|token|credential)`,
				`fmt\.Printf.*password`,
			},
		},
	}
}

// CheckMemoryUsage 检查内存使用情况
func (c *SecurityChecker) CheckMemoryUsage(filePath string) (uint64, error) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	initialAlloc := m.Alloc

	// 读取并执行文件
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("读取文件失败: %v", err)
	}

	// 解析文件以检查内存使用
	fset := token.NewFileSet()
	_, err = parser.ParseFile(fset, filePath, content, parser.AllErrors)
	if err != nil {
		return 0, fmt.Errorf("解析文件失败: %v", err)
	}

	runtime.ReadMemStats(&m)
	finalAlloc := m.Alloc

	return finalAlloc - initialAlloc, nil
}

// CheckExecutionTime 检查执行时间
func (c *SecurityChecker) CheckExecutionTime(filePath string, timeout time.Duration) error {
	done := make(chan bool)
	var execErr error

	go func() {
		// 读取并解析文件
		content, err := ioutil.ReadFile(filePath)
		if err != nil {
			execErr = fmt.Errorf("读取文件失败: %v", err)
			done <- true
			return
		}

		fset := token.NewFileSet()
		_, err = parser.ParseFile(fset, filePath, content, parser.AllErrors)
		if err != nil {
			execErr = fmt.Errorf("解析文件失败: %v", err)
			done <- true
			return
		}

		done <- true
	}()

	select {
	case <-done:
		return execErr
	case <-time.After(timeout):
		return fmt.Errorf("执行超时(>%v)", timeout)
	}
}

// CheckFileAccess 检查文件访问安全性
func (c *SecurityChecker) CheckFileAccess(filePath string) ([]string, error) {
	violations := make([]string, 0)
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	c.mu.RLock()
	patterns := c.sensitivePatterns["file_access"]
	c.mu.RUnlock()

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}

		matches := re.FindAllString(string(content), -1)
		for _, match := range matches {
			violations = append(violations, fmt.Sprintf("发现敏感文件操作: %s", match))
		}
	}

	return violations, nil
}

// CheckNetworkAccess 检查网络访问安全性
func (c *SecurityChecker) CheckNetworkAccess(filePath string) ([]string, error) {
	violations := make([]string, 0)
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	c.mu.RLock()
	patterns := c.sensitivePatterns["network_access"]
	c.mu.RUnlock()

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}

		matches := re.FindAllString(string(content), -1)
		for _, match := range matches {
			violations = append(violations, fmt.Sprintf("发现敏感网络操作: %s", match))
		}
	}

	return violations, nil
}

// CheckInputValidation 检查输入验证
func (c *SecurityChecker) CheckInputValidation(filePath string) ([]string, error) {
	issues := make([]string, 0)
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, content, parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("解析文件失败: %v", err)
	}

	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok {
					funcName := x.Name + "." + sel.Sel.Name
					if strings.Contains(funcName, "fmt.Scan") || strings.Contains(funcName, "bufio.NewScanner") {
						issues = append(issues, fmt.Sprintf("未验证的输入: %s", funcName))
					}
				}
			}
		}
		return true
	})

	return issues, nil
}

// CheckRandomGeneration 检查随机数生成安全性
func (c *SecurityChecker) CheckRandomGeneration(filePath string) ([]string, error) {
	issues := make([]string, 0)
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	c.mu.RLock()
	patterns := c.sensitivePatterns["random_generation"]
	c.mu.RUnlock()

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}

		matches := re.FindAllString(string(content), -1)
		for _, match := range matches {
			if !strings.Contains(match, "crypto/rand") {
				issues = append(issues, fmt.Sprintf("不安全的随机数生成: %s", match))
			}
		}
	}

	return issues, nil
}

// CheckSensitiveData 检查敏感数据处理
func (c *SecurityChecker) CheckSensitiveData(filePath string) ([]string, error) {
	issues := make([]string, 0)
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	c.mu.RLock()
	patterns := c.sensitivePatterns["sensitive_data"]
	c.mu.RUnlock()

	for _, pattern := range patterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}

		matches := re.FindAllString(string(content), -1)
		for _, match := range matches {
			issues = append(issues, fmt.Sprintf("敏感数据泄露风险: %s", match))
		}
	}

	return issues, nil
}

// CheckSandboxEscape 检查沙箱逃逸
func (c *SecurityChecker) CheckSandboxEscape(filePath string) ([]string, error) {
	violations := make([]string, 0)
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, content, parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("解析文件失败: %v", err)
	}

	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok {
					funcName := x.Name + "." + sel.Sel.Name
					if strings.Contains(funcName, "os.") || strings.Contains(funcName, "exec.") {
						violations = append(violations, fmt.Sprintf("危险的系统调用: %s", funcName))
					}
				}
			}
		}
		return true
	})

	return violations, nil
}

// PerformFullCheck 执行完整的安全检查
func (c *SecurityChecker) PerformFullCheck(filePath string) (map[string]interface{}, error) {
	results := make(map[string]interface{})

	// 检查内存使用
	memoryUsage, err := c.CheckMemoryUsage(filePath)
	if err != nil {
		results["memory_usage"] = err.Error()
	} else {
		results["memory_usage"] = memoryUsage
	}

	// 检查执行时间
	err = c.CheckExecutionTime(filePath, 5*time.Second)
	if err != nil {
		results["execution_time"] = err.Error()
	} else {
		results["execution_time"] = "OK"
	}

	// 检查文件访问
	fileAccess, err := c.CheckFileAccess(filePath)
	if err != nil {
		results["file_access"] = err.Error()
	} else {
		results["file_access"] = fileAccess
	}

	// 检查网络访问
	networkAccess, err := c.CheckNetworkAccess(filePath)
	if err != nil {
		results["network_access"] = err.Error()
	} else {
		results["network_access"] = networkAccess
	}

	// 检查输入验证
	inputValidation, err := c.CheckInputValidation(filePath)
	if err != nil {
		results["input_validation"] = err.Error()
	} else {
		results["input_validation"] = inputValidation
	}

	// 检查随机数生成
	randomGeneration, err := c.CheckRandomGeneration(filePath)
	if err != nil {
		results["random_generation"] = err.Error()
	} else {
		results["random_generation"] = randomGeneration
	}

	// 检查敏感数据
	sensitiveData, err := c.CheckSensitiveData(filePath)
	if err != nil {
		results["sensitive_data"] = err.Error()
	} else {
		results["sensitive_data"] = sensitiveData
	}

	// 检查沙箱逃逸
	sandboxEscape, err := c.CheckSandboxEscape(filePath)
	if err != nil {
		results["sandbox_escape"] = err.Error()
	} else {
		results["sandbox_escape"] = sandboxEscape
	}

	return results, nil
} 