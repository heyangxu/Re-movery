package utils

import (
	"os"
	"testing"
	"time"
)

func TestNewSecurityChecker(t *testing.T) {
	checker := NewSecurityChecker()
	if checker == nil {
		t.Error("NewSecurityChecker返回了nil")
	}

	if len(checker.sensitivePatterns) == 0 {
		t.Error("敏感模式映射为空")
	}

	expectedPatterns := []string{"file_access", "network_access", "code_execution", "input_validation", "random_generation", "sensitive_data"}
	for _, pattern := range expectedPatterns {
		if patterns, ok := checker.sensitivePatterns[pattern]; !ok || len(patterns) == 0 {
			t.Errorf("缺少预期的模式类型: %s", pattern)
		}
	}
}

func createTestFile(content string) (string, error) {
	tmpfile, err := os.CreateTemp("", "test_*.go")
	if err != nil {
		return "", err
	}

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		os.Remove(tmpfile.Name())
		return "", err
	}

	if err := tmpfile.Close(); err != nil {
		os.Remove(tmpfile.Name())
		return "", err
	}

	return tmpfile.Name(), nil
}

func TestCheckMemoryUsage(t *testing.T) {
	checker := NewSecurityChecker()
	content := `package main

import "fmt"

func main() {
	var arr []int
	for i := 0; i < 1000; i++ {
		arr = append(arr, i)
	}
	fmt.Println(arr)
}`

	filename, err := createTestFile(content)
	if err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
	defer os.Remove(filename)

	usage, err := checker.CheckMemoryUsage(filename)
	if err != nil {
		t.Errorf("检查内存使用失败: %v", err)
	}

	if usage == 0 {
		t.Error("内存使用量不应为0")
	}
}

func TestCheckExecutionTime(t *testing.T) {
	checker := NewSecurityChecker()
	content := `package main

import "time"

func main() {
	time.Sleep(time.Second)
}`

	filename, err := createTestFile(content)
	if err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
	defer os.Remove(filename)

	// 测试正常超时
	err = checker.CheckExecutionTime(filename, 5*time.Second)
	if err != nil {
		t.Errorf("执行时间检查失败: %v", err)
	}

	// 测试超时情况
	err = checker.CheckExecutionTime(filename, 1*time.Millisecond)
	if err == nil {
		t.Error("预期应该发生超时错误")
	}
}

func TestCheckFileAccess(t *testing.T) {
	checker := NewSecurityChecker()
	content := `package main

import (
	"os"
	"io/ioutil"
)

func main() {
	os.Open("test.txt")
	ioutil.ReadFile("config.json")
}`

	filename, err := createTestFile(content)
	if err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
	defer os.Remove(filename)

	violations, err := checker.CheckFileAccess(filename)
	if err != nil {
		t.Errorf("文件访问检查失败: %v", err)
	}

	if len(violations) == 0 {
		t.Error("应该检测到文件访问违规")
	}
}

func TestCheckNetworkAccess(t *testing.T) {
	checker := NewSecurityChecker()
	content := `package main

import (
	"net"
	"net/http"
)

func main() {
	net.Dial("tcp", "localhost:8080")
	http.Get("http://example.com")
}`

	filename, err := createTestFile(content)
	if err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
	defer os.Remove(filename)

	violations, err := checker.CheckNetworkAccess(filename)
	if err != nil {
		t.Errorf("网络访问检查失败: %v", err)
	}

	if len(violations) == 0 {
		t.Error("应该检测到网络访问违规")
	}
}

func TestCheckInputValidation(t *testing.T) {
	checker := NewSecurityChecker()
	content := `package main

import (
	"fmt"
	"bufio"
	"os"
)

func main() {
	var input string
	fmt.Scanln(&input)
	scanner := bufio.NewScanner(os.Stdin)
}`

	filename, err := createTestFile(content)
	if err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
	defer os.Remove(filename)

	issues, err := checker.CheckInputValidation(filename)
	if err != nil {
		t.Errorf("输入验证检查失败: %v", err)
	}

	if len(issues) == 0 {
		t.Error("应该检测到未验证的输入")
	}
}

func TestCheckRandomGeneration(t *testing.T) {
	checker := NewSecurityChecker()
	content := `package main

import (
	"math/rand"
	"crypto/rand"
)

func main() {
	rand.Int()
	rand.Read(make([]byte, 32))
}`

	filename, err := createTestFile(content)
	if err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
	defer os.Remove(filename)

	issues, err := checker.CheckRandomGeneration(filename)
	if err != nil {
		t.Errorf("随机数生成检查失败: %v", err)
	}

	if len(issues) == 0 {
		t.Error("应该检测到不安全的随机数生成")
	}
}

func TestCheckSensitiveData(t *testing.T) {
	checker := NewSecurityChecker()
	content := `package main

import "fmt"

func main() {
	password := "secret123"
	fmt.Printf("Password: %s\n", password)
}`

	filename, err := createTestFile(content)
	if err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
	defer os.Remove(filename)

	issues, err := checker.CheckSensitiveData(filename)
	if err != nil {
		t.Errorf("敏感数据检查失败: %v", err)
	}

	if len(issues) == 0 {
		t.Error("应该检测到敏感数据泄露风险")
	}
}

func TestCheckSandboxEscape(t *testing.T) {
	checker := NewSecurityChecker()
	content := `package main

import (
	"os"
	"os/exec"
)

func main() {
	os.Remove("test.txt")
	exec.Command("ls").Run()
}`

	filename, err := createTestFile(content)
	if err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
	defer os.Remove(filename)

	violations, err := checker.CheckSandboxEscape(filename)
	if err != nil {
		t.Errorf("沙箱逃逸检查失败: %v", err)
	}

	if len(violations) == 0 {
		t.Error("应该检测到沙箱逃逸风险")
	}
}

func TestPerformFullCheck(t *testing.T) {
	checker := NewSecurityChecker()
	content := `package main

import (
	"fmt"
	"os"
	"net/http"
	"math/rand"
)

func main() {
	password := "secret123"
	os.Open("test.txt")
	http.Get("http://example.com")
	rand.Int()
	fmt.Printf("Password: %s\n", password)
}`

	filename, err := createTestFile(content)
	if err != nil {
		t.Fatalf("创建测试文件失败: %v", err)
	}
	defer os.Remove(filename)

	results, err := checker.PerformFullCheck(filename)
	if err != nil {
		t.Errorf("完整检查失败: %v", err)
	}

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
		if _, ok := results[check]; !ok {
			t.Errorf("缺少检查结果: %s", check)
		}
	}
} 