package utils

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSecurityChecker(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "security_test")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 创建测试代码文件
	testCode := `package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"time"
)

func unsafeMemory() {
	// 大量内存分配
	largeSlice := make([]int, 1e7)
	for i := range largeSlice {
		largeSlice[i] = i
	}
}

func unsafeExecution() {
	// 长时间执行
	time.Sleep(5 * time.Second)
}

func unsafeFileAccess() {
	// 危险的文件操作
	file, _ := os.Open("/etc/passwd")
	defer file.Close()
}

func unsafeNetwork() {
	// 未验证的网络请求
	http.Get("http://example.com")
}

func unsafeInput() {
	// 未验证的输入
	var input string
	fmt.Scanln(&input)
	exec.Command("bash", "-c", input).Run()
}

func unsafeRandom() {
	// 不安全的随机数生成
	rand.Seed(time.Now().UnixNano())
	fmt.Println(rand.Int())
}

func unsafeSensitiveData() {
	// 敏感数据暴露
	password := "super_secret_123"
	fmt.Printf("Password: %s\n", password)
}

func unsafeSandbox() {
	// 沙箱逃逸尝试
	exec.Command("rm", "-rf", "/").Run()
}
`

	testFile := filepath.Join(tempDir, "test.go")
	err = os.WriteFile(testFile, []byte(testCode), 0644)
	if err != nil {
		t.Fatalf("写入测试代码文件失败: %v", err)
	}

	// 创建检查器实例
	checker := NewSecurityChecker()

	// 测试内存使用检查
	t.Run("TestCheckMemoryUsage", func(t *testing.T) {
		result := checker.CheckMemoryUsage(testFile)
		assert.True(t, result.HasIssues)
		assert.Contains(t, result.Details, "largeSlice")
		assert.Greater(t, len(result.Patterns), 0)
	})

	// 测试执行时间检查
	t.Run("TestCheckExecutionTime", func(t *testing.T) {
		result := checker.CheckExecutionTime(testFile)
		assert.True(t, result.HasIssues)
		assert.Contains(t, result.Details, "time.Sleep")
		assert.Greater(t, len(result.Patterns), 0)
	})

	// 测试文件访问检查
	t.Run("TestCheckFileAccess", func(t *testing.T) {
		result := checker.CheckFileAccess(testFile)
		assert.True(t, result.HasIssues)
		assert.Contains(t, result.Details, "/etc/passwd")
		assert.Greater(t, len(result.Patterns), 0)
	})

	// 测试网络访问检查
	t.Run("TestCheckNetworkAccess", func(t *testing.T) {
		result := checker.CheckNetworkAccess(testFile)
		assert.True(t, result.HasIssues)
		assert.Contains(t, result.Details, "http.Get")
		assert.Greater(t, len(result.Patterns), 0)
	})

	// 测试输入验证检查
	t.Run("TestCheckInputValidation", func(t *testing.T) {
		result := checker.CheckInputValidation(testFile)
		assert.True(t, result.HasIssues)
		assert.Contains(t, result.Details, "exec.Command")
		assert.Greater(t, len(result.Patterns), 0)
	})

	// 测试随机数生成检查
	t.Run("TestCheckRandomGeneration", func(t *testing.T) {
		result := checker.CheckRandomGeneration(testFile)
		assert.True(t, result.HasIssues)
		assert.Contains(t, result.Details, "math/rand")
		assert.Greater(t, len(result.Patterns), 0)
	})

	// 测试敏感数据检查
	t.Run("TestCheckSensitiveData", func(t *testing.T) {
		result := checker.CheckSensitiveData(testFile)
		assert.True(t, result.HasIssues)
		assert.Contains(t, result.Details, "password")
		assert.Greater(t, len(result.Patterns), 0)
	})

	// 测试沙箱逃逸检查
	t.Run("TestCheckSandboxEscape", func(t *testing.T) {
		result := checker.CheckSandboxEscape(testFile)
		assert.True(t, result.HasIssues)
		assert.Contains(t, result.Details, "exec.Command")
		assert.Greater(t, len(result.Patterns), 0)
	})

	// 测试完整安全检查
	t.Run("TestPerformFullCheck", func(t *testing.T) {
		results := checker.PerformFullCheck(testFile)
		assert.NotNil(t, results)
		assert.Greater(t, len(results), 0)

		// 验证所有检查项都已执行
		expectedChecks := []string{
			"memory_usage",
			"execution_time",
			"file_access",
			"network_access",
			"input_validation",
			"random_generation",
			"sensitive_data",
			"sandbox_escape",
		}

		for _, check := range expectedChecks {
			result, ok := results[check]
			assert.True(t, ok)
			assert.True(t, result.HasIssues)
			assert.Greater(t, len(result.Patterns), 0)
		}
	})

	// 测试并发检查
	t.Run("TestConcurrentChecks", func(t *testing.T) {
		// 创建多个测试文件
		testFiles := make([]string, 5)
		for i := range testFiles {
			filePath := filepath.Join(tempDir, fmt.Sprintf("test_%d.go", i))
			err := os.WriteFile(filePath, []byte(testCode), 0644)
			assert.NoError(t, err)
			testFiles[i] = filePath
		}

		// 记录串行执行时间
		startSerial := time.Now()
		for _, file := range testFiles {
			checker.PerformFullCheck(file)
		}
		serialDuration := time.Since(startSerial)

		// 记录并行执行时间
		startParallel := time.Now()
		resultChan := make(chan map[string]SecurityCheckResult, len(testFiles))
		for _, file := range testFiles {
			go func(f string) {
				resultChan <- checker.PerformFullCheck(f)
			}(file)
		}

		// 收集结果
		results := make([]map[string]SecurityCheckResult, 0, len(testFiles))
		for i := 0; i < len(testFiles); i++ {
			result := <-resultChan
			results = append(results, result)
		}
		parallelDuration := time.Since(startParallel)

		// 验证结果
		assert.Equal(t, len(testFiles), len(results))
		for _, result := range results {
			assert.NotNil(t, result)
			assert.Greater(t, len(result), 0)
		}

		// 验证并行执行更快
		assert.Less(t, parallelDuration, serialDuration)
	})

	// 测试错误处理
	t.Run("TestErrorHandling", func(t *testing.T) {
		// 测试不存在的文件
		nonExistentFile := filepath.Join(tempDir, "non_existent.go")
		result := checker.PerformFullCheck(nonExistentFile)
		assert.NotNil(t, result)
		for _, check := range result {
			assert.False(t, check.HasIssues)
			assert.Contains(t, check.Details, "file not found")
		}

		// 测试无效的Go代码
		invalidCode := "invalid go code"
		invalidFile := filepath.Join(tempDir, "invalid.go")
		err := os.WriteFile(invalidFile, []byte(invalidCode), 0644)
		assert.NoError(t, err)

		result = checker.PerformFullCheck(invalidFile)
		assert.NotNil(t, result)
		for _, check := range result {
			assert.False(t, check.HasIssues)
			assert.Contains(t, check.Details, "parse error")
		}
	})
}

func TestSecurityCheckerEdgeCases(t *testing.T) {
	checker := NewSecurityChecker()

	// 测试空文件
	t.Run("TestEmptyFile", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "empty_test")
		assert.NoError(t, err)
		defer os.RemoveAll(tempDir)

		emptyFile := filepath.Join(tempDir, "empty.go")
		err = os.WriteFile(emptyFile, []byte(""), 0644)
		assert.NoError(t, err)

		result := checker.PerformFullCheck(emptyFile)
		assert.NotNil(t, result)
		for _, check := range result {
			assert.False(t, check.HasIssues)
		}
	})

	// 测试大文件处理
	t.Run("TestLargeFile", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "large_test")
		assert.NoError(t, err)
		defer os.RemoveAll(tempDir)

		// 生成大文件
		largeCode := `package main

import "fmt"

func main() {
`
		for i := 0; i < 10000; i++ {
			largeCode += fmt.Sprintf("\tfmt.Println(%d)\n", i)
		}
		largeCode += "}\n"

		largeFile := filepath.Join(tempDir, "large.go")
		err = os.WriteFile(largeFile, []byte(largeCode), 0644)
		assert.NoError(t, err)

		startTime := time.Now()
		result := checker.PerformFullCheck(largeFile)
		duration := time.Since(startTime)

		assert.NotNil(t, result)
		assert.Less(t, duration, 30*time.Second) // 确保大文件处理不会超时
	})

	// 测试并发限制
	t.Run("TestConcurrencyLimit", func(t *testing.T) {
		tempDir, err := os.MkdirTemp("", "concurrency_test")
		assert.NoError(t, err)
		defer os.RemoveAll(tempDir)

		// 创建多个测试文件
		numFiles := 100
		testFiles := make([]string, numFiles)
		testCode := `package main
func main() {}`

		for i := range testFiles {
			filePath := filepath.Join(tempDir, fmt.Sprintf("test_%d.go", i))
			err := os.WriteFile(filePath, []byte(testCode), 0644)
			assert.NoError(t, err)
			testFiles[i] = filePath
		}

		// 并发执行检查
		startTime := time.Now()
		resultChan := make(chan map[string]SecurityCheckResult, numFiles)
		for _, file := range testFiles {
			go func(f string) {
				resultChan <- checker.PerformFullCheck(f)
			}(file)
		}

		// 收集结果
		results := make([]map[string]SecurityCheckResult, 0, numFiles)
		for i := 0; i < numFiles; i++ {
			result := <-resultChan
			results = append(results, result)
		}
		duration := time.Since(startTime)

		assert.Equal(t, numFiles, len(results))
		assert.Less(t, duration, 60*time.Second) // 确保并发处理不会超时
	})
} 