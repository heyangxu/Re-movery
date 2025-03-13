package security

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"re-movery/internal/detectors"
	"re-movery/internal/utils"
)

// TestSecurity 包含所有安全相关的测试
type TestSecurity struct {
	tempDir string
	detector *detectors.VulnerabilityDetector
	checker *utils.SecurityChecker
}

// createTestFile 创建测试文件
func (ts *TestSecurity) createTestFile(content string) (string, error) {
	file, err := ioutil.TempFile(ts.tempDir, "test-*.go")
	if err != nil {
		return "", fmt.Errorf("创建临时文件失败: %v", err)
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		return "", fmt.Errorf("写入文件内容失败: %v", err)
	}

	return file.Name(), nil
}

func TestMemoryLimit(t *testing.T) {
	ts := &TestSecurity{
		tempDir: t.TempDir(),
		detector: detectors.NewVulnerabilityDetector(),
		checker: utils.NewSecurityChecker(),
	}

	// 创建可能导致内存溢出的测试文件
	content := `
	package main

	func memoryIntensive() {
		largeSlice := make([]int, 1<<30) // 尝试分配大量内存
		for i := range largeSlice {
			largeSlice[i] = i
		}
	}
	`
	
	filePath, err := ts.createTestFile(content)
	require.NoError(t, err)

	// 检查内存使用
	memoryUsage, err := ts.checker.CheckMemoryUsage(filePath)
	require.NoError(t, err)
	assert.Less(t, memoryUsage, uint64(8<<30)) // 8GB限制
}

func TestExecutionTimeout(t *testing.T) {
	ts := &TestSecurity{
		tempDir: t.TempDir(),
		detector: detectors.NewVulnerabilityDetector(),
		checker: utils.NewSecurityChecker(),
	}

	// 创建可能导致无限循环的测试文件
	content := `
	package main

	func infiniteLoop() {
		for {
			// 无限循环
		}
	}
	`

	filePath, err := ts.createTestFile(content)
	require.NoError(t, err)

	// 检查执行时间
	err = ts.checker.CheckExecutionTime(filePath, 5*time.Second)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestFileAccess(t *testing.T) {
	ts := &TestSecurity{
		tempDir: t.TempDir(),
		detector: detectors.NewVulnerabilityDetector(),
		checker: utils.NewSecurityChecker(),
	}

	// 创建测试文件
	content := `
	package main

	import "os"

	func accessSensitiveFile() {
		file, _ := os.Open("/etc/passwd")
		defer file.Close()
	}
	`

	filePath, err := ts.createTestFile(content)
	require.NoError(t, err)

	// 检查文件访问
	violations, err := ts.checker.CheckFileAccess(filePath)
	require.NoError(t, err)
	assert.Greater(t, len(violations), 0)
	assert.Contains(t, violations[0], "/etc/passwd")
}

func TestNetworkAccess(t *testing.T) {
	ts := &TestSecurity{
		tempDir: t.TempDir(),
		detector: detectors.NewVulnerabilityDetector(),
		checker: utils.NewSecurityChecker(),
	}

	// 创建测试文件
	content := `
	package main

	import "net"

	func connectExternal() {
		conn, _ := net.Dial("tcp", "example.com:80")
		defer conn.Close()
	}
	`

	filePath, err := ts.createTestFile(content)
	require.NoError(t, err)

	// 检查网络访问
	violations, err := ts.checker.CheckNetworkAccess(filePath)
	require.NoError(t, err)
	assert.Greater(t, len(violations), 0)
	assert.Contains(t, violations[0], "net.Dial")
}

func TestCodeInjection(t *testing.T) {
	ts := &TestSecurity{
		tempDir: t.TempDir(),
		detector: detectors.NewVulnerabilityDetector(),
		checker: utils.NewSecurityChecker(),
	}

	// 创建测试文件
	content := `
	package main

	import "os/exec"

	func executeInput(userInput string) {
		cmd := exec.Command("bash", "-c", userInput)
		cmd.Run()
	}
	`

	filePath, err := ts.createTestFile(content)
	require.NoError(t, err)

	// 检查代码注入
	vulnerabilities, err := ts.detector.DetectFile(filePath)
	require.NoError(t, err)
	assert.Greater(t, len(vulnerabilities), 0)
	assert.Equal(t, "HIGH", vulnerabilities[0].Severity)
}

func TestInputValidation(t *testing.T) {
	ts := &TestSecurity{
		tempDir: t.TempDir(),
		detector: detectors.NewVulnerabilityDetector(),
		checker: utils.NewSecurityChecker(),
	}

	// 创建测试文件
	content := `
	package main

	import "fmt"

	func processInput(userInput string) {
		fmt.Sprintf("%s", userInput) // 未经验证的输入
	}
	`

	filePath, err := ts.createTestFile(content)
	require.NoError(t, err)

	// 检查输入验证
	issues, err := ts.checker.CheckInputValidation(filePath)
	require.NoError(t, err)
	assert.Greater(t, len(issues), 0)
}

func TestSecureRandom(t *testing.T) {
	ts := &TestSecurity{
		tempDir: t.TempDir(),
		detector: detectors.NewVulnerabilityDetector(),
		checker: utils.NewSecurityChecker(),
	}

	// 创建测试文件
	content := `
	package main

	import "math/rand"

	func generateToken() string {
		const chars = "0123456789ABCDEF"
		result := make([]byte, 32)
		for i := range result {
			result[i] = chars[rand.Intn(len(chars))]
		}
		return string(result)
	}
	`

	filePath, err := ts.createTestFile(content)
	require.NoError(t, err)

	// 检查随机数生成
	issues, err := ts.checker.CheckRandomGeneration(filePath)
	require.NoError(t, err)
	assert.Greater(t, len(issues), 0)
	assert.Contains(t, issues[0], "math/rand")
}

func TestSensitiveData(t *testing.T) {
	ts := &TestSecurity{
		tempDir: t.TempDir(),
		detector: detectors.NewVulnerabilityDetector(),
		checker: utils.NewSecurityChecker(),
	}

	// 创建测试文件
	content := `
	package main

	import "fmt"

	func processPassword(password string) {
		fmt.Printf("Password is: %s\n", password) // 敏感信息泄露
	}
	`

	filePath, err := ts.createTestFile(content)
	require.NoError(t, err)

	// 检查敏感数据处理
	issues, err := ts.checker.CheckSensitiveData(filePath)
	require.NoError(t, err)
	assert.Greater(t, len(issues), 0)
	assert.Contains(t, issues[0], "password")
}

func TestSandboxEscape(t *testing.T) {
	ts := &TestSecurity{
		tempDir: t.TempDir(),
		detector: detectors.NewVulnerabilityDetector(),
		checker: utils.NewSecurityChecker(),
	}

	// 创建测试文件
	content := `
	package main

	import (
		"os"
		"os/exec"
	)

	func dangerousOperation() {
		os.RemoveAll("/")
		exec.Command("chmod", "777", "/etc/passwd").Run()
	}
	`

	filePath, err := ts.createTestFile(content)
	require.NoError(t, err)

	// 检查沙箱逃逸
	violations, err := ts.checker.CheckSandboxEscape(filePath)
	require.NoError(t, err)
	assert.Greater(t, len(violations), 0)
	assert.Contains(t, violations[0], "os.RemoveAll")
} 