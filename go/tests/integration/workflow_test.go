package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/heyangxu/Re-movery/go/internal/analyzers"
	"github.com/heyangxu/Re-movery/go/internal/detectors"
	"github.com/heyangxu/Re-movery/go/internal/reporters"
	"github.com/heyangxu/Re-movery/go/internal/utils"
)

func TestWorkflow(t *testing.T) {
	// 创建临时目录
	tempDir, err := os.MkdirTemp("", "workflow_test")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 创建测试项目结构
	err = createTestProject(tempDir)
	if err != nil {
		t.Fatalf("创建测试项目失败: %v", err)
	}

	// 初始化组件
	detector := detectors.NewVulnerabilityDetector()
	checker := utils.NewSecurityChecker()
	analyzer := analyzers.NewCodeAnalyzer()
	reporter := reporters.NewHTMLReporter()

	// 测试完整工作流程
	t.Run("TestFullWorkflow", func(t *testing.T) {
		// 加载配置
		configFile := filepath.Join(tempDir, "config.json")
		configData, err := os.ReadFile(configFile)
		assert.NoError(t, err)

		var config map[string]interface{}
		err = json.Unmarshal(configData, &config)
		assert.NoError(t, err)

		// 加载签名
		signatureFile := filepath.Join(tempDir, "signatures.json")
		err = detector.LoadSignatures(signatureFile)
		assert.NoError(t, err)

		// 分析源代码文件
		srcDir := filepath.Join(tempDir, "src")
		vulnerableFile := filepath.Join(srcDir, "vulnerable.go")
		safeFile := filepath.Join(srcDir, "safe.go")

		// 检测漏洞
		vulnerableMatches, err := detector.DetectFile(vulnerableFile)
		assert.NoError(t, err)
		safeMatches, err := detector.DetectFile(safeFile)
		assert.NoError(t, err)

		assert.Greater(t, len(vulnerableMatches), 0)
		assert.Equal(t, 0, len(safeMatches))

		// 执行安全检查
		vulnerableSecurity := checker.PerformFullCheck(vulnerableFile)
		safeSecurity := checker.PerformFullCheck(safeFile)

		assert.True(t, hasIssues(vulnerableSecurity))
		assert.False(t, hasIssues(safeSecurity))

		// 代码分析
		vulnerableAnalysis, err := analyzer.AnalyzeFile(vulnerableFile)
		assert.NoError(t, err)
		safeAnalysis, err := analyzer.AnalyzeFile(safeFile)
		assert.NoError(t, err)

		assert.Greater(t, vulnerableAnalysis.Complexity, safeAnalysis.Complexity)

		// 生成报告
		reportData := map[string]interface{}{
			"project_name":  config["project_name"],
			"scan_time":    time.Now().Format("2006-01-02 15:04:05"),
			"files_scanned": []string{vulnerableFile, safeFile},
			"vulnerability_results": map[string]interface{}{
				"vulnerable.go": vulnerableMatches,
				"safe.go":      safeMatches,
			},
			"security_results": map[string]interface{}{
				"vulnerable.go": vulnerableSecurity,
				"safe.go":      safeSecurity,
			},
			"analysis_results": map[string]interface{}{
				"vulnerable.go": vulnerableAnalysis,
				"safe.go":      safeAnalysis,
			},
		}

		reportFile := filepath.Join(tempDir, "reports", "report.html")
		err = reporter.GenerateReport(reportData, reportFile)
		assert.NoError(t, err)

		assert.FileExists(t, reportFile)
		fileInfo, err := os.Stat(reportFile)
		assert.NoError(t, err)
		assert.Greater(t, fileInfo.Size(), int64(0))
	})

	// 测试并行处理
	t.Run("TestParallelProcessing", func(t *testing.T) {
		// 创建多个测试文件
		srcDir := filepath.Join(tempDir, "src")
		testFiles := make([]string, 5)
		testCode := `package main

import "os/exec"

func main() {
	exec.Command("ls").Run()
}
`
		for i := range testFiles {
			filePath := filepath.Join(srcDir, "test_%d.go")
			err := os.WriteFile(filePath, []byte(testCode), 0644)
			assert.NoError(t, err)
			testFiles[i] = filePath
		}

		// 串行处理时间
		startSerial := time.Now()
		for _, file := range testFiles {
			_, err := detector.DetectFile(file)
			assert.NoError(t, err)
			checker.PerformFullCheck(file)
			_, err = analyzer.AnalyzeFile(file)
			assert.NoError(t, err)
		}
		serialDuration := time.Since(startSerial)

		// 并行处理时间
		startParallel := time.Now()
		resultChan := make(chan struct{}, len(testFiles))
		for _, file := range testFiles {
			go func(f string) {
				_, err := detector.DetectFile(f)
				assert.NoError(t, err)
				checker.PerformFullCheck(f)
				_, err = analyzer.AnalyzeFile(f)
				assert.NoError(t, err)
				resultChan <- struct{}{}
			}(file)
		}

		// 等待所有并行任务完成
		for i := 0; i < len(testFiles); i++ {
			<-resultChan
		}
		parallelDuration := time.Since(startParallel)

		assert.Less(t, parallelDuration, serialDuration)
	})

	// 测试错误处理
	t.Run("TestErrorHandling", func(t *testing.T) {
		// 测试无效的配置文件
		invalidConfig := filepath.Join(tempDir, "invalid_config.json")
		err := os.WriteFile(invalidConfig, []byte("invalid json"), 0644)
		assert.NoError(t, err)

		_, err = os.ReadFile(invalidConfig)
		assert.NoError(t, err)
		var config map[string]interface{}
		err = json.Unmarshal([]byte("invalid json"), &config)
		assert.Error(t, err)

		// 测试不存在的源代码文件
		nonExistentFile := filepath.Join(tempDir, "non_existent.go")
		_, err = detector.DetectFile(nonExistentFile)
		assert.Error(t, err)

		// 测试无效的源代码
		invalidCode := filepath.Join(tempDir, "invalid.go")
		err = os.WriteFile(invalidCode, []byte("invalid go code"), 0644)
		assert.NoError(t, err)

		_, err = analyzer.AnalyzeFile(invalidCode)
		assert.Error(t, err)
	})
}

func createTestProject(dir string) error {
	// 创建配置文件
	config := map[string]interface{}{
		"project_name":        "Test Project",
		"scan_paths":         []string{"src"},
		"exclude_paths":      []string{"tests", "docs"},
		"report_format":      "html",
		"report_path":        "reports",
		"severity_threshold": "medium",
		"parallel_processing": true,
		"max_workers":        4,
	}

	configFile := filepath.Join(dir, "config.json")
	configData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(configFile, configData, 0644)
	if err != nil {
		return err
	}

	// 创建签名文件
	signatures := map[string]interface{}{
		"signatures": []map[string]interface{}{
			{
				"id":       "CMD001",
				"name":     "命令注入",
				"severity": "high",
				"code_patterns": []string{
					`exec\.Command\([^)]*\)`,
					`os\.exec\.Command\([^)]*\)`,
				},
			},
			{
				"id":       "SQL001",
				"name":     "SQL注入",
				"severity": "high",
				"code_patterns": []string{
					`db\.Query\([^)]*\+[^)]*\)`,
					`db\.Exec\([^)]*\+[^)]*\)`,
				},
			},
		},
	}

	signatureFile := filepath.Join(dir, "signatures.json")
	signatureData, err := json.MarshalIndent(signatures, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(signatureFile, signatureData, 0644)
	if err != nil {
		return err
	}

	// 创建源代码目录
	srcDir := filepath.Join(dir, "src")
	err = os.MkdirAll(srcDir, 0755)
	if err != nil {
		return err
	}

	// 创建漏洞代码文件
	vulnerableCode := `package main

import (
	"database/sql"
	"os/exec"
)

func unsafeCommand(cmd string) {
	exec.Command("bash", "-c", cmd).Run()
}

func unsafeQuery(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = " + id)
}

func main() {
	unsafeCommand("ls -l")
	db, _ := sql.Open("mysql", "user:password@/dbname")
	unsafeQuery(db, "1 OR 1=1")
}
`

	vulnerableFile := filepath.Join(srcDir, "vulnerable.go")
	err = os.WriteFile(vulnerableFile, []byte(vulnerableCode), 0644)
	if err != nil {
		return err
	}

	// 创建安全代码文件
	safeCode := `package main

import (
	"database/sql"
)

func safeQuery(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = ?", id)
}

func main() {
	db, _ := sql.Open("mysql", "user:password@/dbname")
	safeQuery(db, "1")
}
`

	safeFile := filepath.Join(srcDir, "safe.go")
	err = os.WriteFile(safeFile, []byte(safeCode), 0644)
	if err != nil {
		return err
	}

	// 创建报告目录
	reportDir := filepath.Join(dir, "reports")
	return os.MkdirAll(reportDir, 0755)
}

func hasIssues(results map[string]utils.SecurityCheckResult) bool {
	for _, result := range results {
		if result.HasIssues {
			return true
		}
	}
	return false
} 