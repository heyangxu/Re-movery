package core

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// 测试扫描器创建
func TestNewScanner(t *testing.T) {
	scanner := NewScanner()
	assert.NotNil(t, scanner)
	assert.False(t, scanner.IsParallel())
	assert.False(t, scanner.IsIncremental())
}

// 测试设置并行处理
func TestSetParallel(t *testing.T) {
	scanner := NewScanner()
	assert.False(t, scanner.IsParallel())
	
	scanner.SetParallel(true)
	assert.True(t, scanner.IsParallel())
	
	scanner.SetParallel(false)
	assert.False(t, scanner.IsParallel())
}

// 测试设置增量扫描
func TestSetIncremental(t *testing.T) {
	scanner := NewScanner()
	assert.False(t, scanner.IsIncremental())
	
	scanner.SetIncremental(true)
	assert.True(t, scanner.IsIncremental())
	
	scanner.SetIncremental(false)
	assert.False(t, scanner.IsIncremental())
}

// 测试注册检测器
func TestRegisterDetector(t *testing.T) {
	scanner := NewScanner()
	
	// 创建模拟检测器
	detector := &mockDetector{}
	
	// 注册检测器
	scanner.RegisterDetector(detector)
	
	// 检查支持的语言
	languages := scanner.SupportedLanguages()
	assert.Contains(t, languages, "mock")
}

// 测试扫描文件
func TestScanFile(t *testing.T) {
	// 创建临时文件
	content := []byte("print(eval('1+1'))")
	tmpfile, err := ioutil.TempFile("", "example.py")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	
	_, err = tmpfile.Write(content)
	assert.NoError(t, err)
	err = tmpfile.Close()
	assert.NoError(t, err)
	
	// 创建扫描器和模拟检测器
	scanner := NewScanner()
	detector := &mockDetector{}
	scanner.RegisterDetector(detector)
	
	// 扫描文件
	matches, err := scanner.ScanFile(tmpfile.Name())
	assert.NoError(t, err)
	assert.Len(t, matches, 1)
	assert.Equal(t, "MOCK001", matches[0].Signature.ID)
}

// 测试扫描目录
func TestScanDirectory(t *testing.T) {
	// 创建临时目录
	tmpdir, err := ioutil.TempDir("", "example")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	
	// 创建测试文件
	file1 := filepath.Join(tmpdir, "test1.py")
	err = ioutil.WriteFile(file1, []byte("print(eval('1+1'))"), 0644)
	assert.NoError(t, err)
	
	file2 := filepath.Join(tmpdir, "test2.py")
	err = ioutil.WriteFile(file2, []byte("print('Hello')"), 0644)
	assert.NoError(t, err)
	
	// 创建扫描器和模拟检测器
	scanner := NewScanner()
	detector := &mockDetector{}
	scanner.RegisterDetector(detector)
	
	// 扫描目录
	results, err := scanner.ScanDirectory(tmpdir, nil)
	assert.NoError(t, err)
	assert.Len(t, results, 2)
	
	// 检查结果
	assert.Contains(t, results, file1)
	assert.Contains(t, results, file2)
	assert.Len(t, results[file1], 1)
	assert.Len(t, results[file2], 1)
}

// 测试生成摘要
func TestGenerateSummary(t *testing.T) {
	// 创建测试数据
	results := map[string][]Match{
		"file1.py": {
			{
				Signature: Signature{
					ID:       "PY001",
					Name:     "Dangerous eval() usage",
					Severity: "high",
				},
			},
		},
		"file2.py": {
			{
				Signature: Signature{
					ID:       "PY002",
					Name:     "Dangerous exec() usage",
					Severity: "high",
				},
			},
			{
				Signature: Signature{
					ID:       "PY005",
					Name:     "Insecure random number generation",
					Severity: "medium",
				},
			},
		},
		"file3.py": {
			{
				Signature: Signature{
					ID:       "PY008",
					Name:     "Temporary file creation risk",
					Severity: "medium",
				},
			},
			{
				Signature: Signature{
					ID:       "PY010",
					Name:     "Debug mode enabled",
					Severity: "medium",
				},
			},
			{
				Signature: Signature{
					ID:       "PY012",
					Name:     "Bare except block",
					Severity: "low",
				},
			},
		},
	}
	
	// 生成摘要
	summary := GenerateSummary(results)
	
	// 检查摘要
	assert.Equal(t, 3, summary.TotalFiles)
	assert.Equal(t, 2, summary.High)
	assert.Equal(t, 3, summary.Medium)
	assert.Equal(t, 1, summary.Low)
	
	// 检查漏洞计数
	assert.Equal(t, 1, summary.Vulnerabilities["Dangerous eval() usage"])
	assert.Equal(t, 1, summary.Vulnerabilities["Dangerous exec() usage"])
	assert.Equal(t, 1, summary.Vulnerabilities["Insecure random number generation"])
	assert.Equal(t, 1, summary.Vulnerabilities["Temporary file creation risk"])
	assert.Equal(t, 1, summary.Vulnerabilities["Debug mode enabled"])
	assert.Equal(t, 1, summary.Vulnerabilities["Bare except block"])
}

// 模拟检测器
type mockDetector struct{}

func (d *mockDetector) Name() string {
	return "mock"
}

func (d *mockDetector) SupportedLanguages() []string {
	return []string{"mock", "py", "python"}
}

func (d *mockDetector) DetectFile(filePath string) ([]Match, error) {
	return []Match{
		{
			Signature: Signature{
				ID:          "MOCK001",
				Name:        "Mock vulnerability",
				Severity:    "high",
				Description: "This is a mock vulnerability",
			},
			FilePath:    filePath,
			LineNumber:  1,
			MatchedCode: "mock code",
			Confidence:  0.9,
		},
	}, nil
}

func (d *mockDetector) DetectCode(code string, filePath string) ([]Match, error) {
	return []Match{
		{
			Signature: Signature{
				ID:          "MOCK001",
				Name:        "Mock vulnerability",
				Severity:    "high",
				Description: "This is a mock vulnerability",
			},
			FilePath:    filePath,
			LineNumber:  1,
			MatchedCode: code,
			Confidence:  0.9,
		},
	}, nil
} 