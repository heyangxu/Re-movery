package core

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// 测试创建新配置
func TestNewConfig(t *testing.T) {
	config := NewConfig()
	assert.NotNil(t, config)
	
	// 检查默认值
	assert.False(t, config.Scanner.Parallel)
	assert.False(t, config.Scanner.Incremental)
	assert.Equal(t, 0.7, config.Scanner.ConfidenceThreshold)
	assert.Equal(t, "localhost", config.Web.Host)
	assert.Equal(t, 8080, config.Web.Port)
	assert.False(t, config.Web.Debug)
	assert.Equal(t, "localhost", config.Server.Host)
	assert.Equal(t, 8081, config.Server.Port)
	assert.False(t, config.Server.Debug)
}

// 测试加载JSON配置
func TestLoadConfigJSON(t *testing.T) {
	// 创建临时配置文件
	content := []byte(`{
		"scanner": {
			"parallel": true,
			"incremental": true,
			"confidenceThreshold": 0.8,
			"excludePatterns": ["node_modules", "*.min.js"]
		},
		"web": {
			"host": "0.0.0.0",
			"port": 9090,
			"debug": true
		},
		"server": {
			"host": "0.0.0.0",
			"port": 9091,
			"debug": true
		}
	}`)
	
	tmpfile, err := ioutil.TempFile("", "config-*.json")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	
	_, err = tmpfile.Write(content)
	assert.NoError(t, err)
	err = tmpfile.Close()
	assert.NoError(t, err)
	
	// 加载配置
	config, err := LoadConfig(tmpfile.Name())
	assert.NoError(t, err)
	assert.NotNil(t, config)
	
	// 检查加载的值
	assert.True(t, config.Scanner.Parallel)
	assert.True(t, config.Scanner.Incremental)
	assert.Equal(t, 0.8, config.Scanner.ConfidenceThreshold)
	assert.Equal(t, []string{"node_modules", "*.min.js"}, config.Scanner.ExcludePatterns)
	assert.Equal(t, "0.0.0.0", config.Web.Host)
	assert.Equal(t, 9090, config.Web.Port)
	assert.True(t, config.Web.Debug)
	assert.Equal(t, "0.0.0.0", config.Server.Host)
	assert.Equal(t, 9091, config.Server.Port)
	assert.True(t, config.Server.Debug)
}

// 测试加载YAML配置
func TestLoadConfigYAML(t *testing.T) {
	// 创建临时配置文件
	content := []byte(`scanner:
  parallel: true
  incremental: true
  confidenceThreshold: 0.8
  excludePatterns:
    - node_modules
    - "*.min.js"
web:
  host: 0.0.0.0
  port: 9090
  debug: true
server:
  host: 0.0.0.0
  port: 9091
  debug: true
`)
	
	tmpfile, err := ioutil.TempFile("", "config-*.yaml")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	
	_, err = tmpfile.Write(content)
	assert.NoError(t, err)
	err = tmpfile.Close()
	assert.NoError(t, err)
	
	// 加载配置
	config, err := LoadConfig(tmpfile.Name())
	assert.NoError(t, err)
	assert.NotNil(t, config)
	
	// 检查加载的值
	assert.True(t, config.Scanner.Parallel)
	assert.True(t, config.Scanner.Incremental)
	assert.Equal(t, 0.8, config.Scanner.ConfidenceThreshold)
	assert.Equal(t, []string{"node_modules", "*.min.js"}, config.Scanner.ExcludePatterns)
	assert.Equal(t, "0.0.0.0", config.Web.Host)
	assert.Equal(t, 9090, config.Web.Port)
	assert.True(t, config.Web.Debug)
	assert.Equal(t, "0.0.0.0", config.Server.Host)
	assert.Equal(t, 9091, config.Server.Port)
	assert.True(t, config.Server.Debug)
}

// 测试保存配置
func TestSaveConfig(t *testing.T) {
	// 创建配置
	config := NewConfig()
	config.Scanner.Parallel = true
	config.Scanner.Incremental = true
	config.Scanner.ConfidenceThreshold = 0.8
	config.Scanner.ExcludePatterns = []string{"node_modules", "*.min.js"}
	config.Web.Host = "0.0.0.0"
	config.Web.Port = 9090
	config.Web.Debug = true
	config.Server.Host = "0.0.0.0"
	config.Server.Port = 9091
	config.Server.Debug = true
	
	// 创建临时文件路径
	tmpdir, err := ioutil.TempDir("", "config-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpdir)
	
	// 保存JSON配置
	jsonPath := filepath.Join(tmpdir, "config.json")
	err = SaveConfig(config, jsonPath)
	assert.NoError(t, err)
	
	// 保存YAML配置
	yamlPath := filepath.Join(tmpdir, "config.yaml")
	err = SaveConfig(config, yamlPath)
	assert.NoError(t, err)
	
	// 重新加载JSON配置
	jsonConfig, err := LoadConfig(jsonPath)
	assert.NoError(t, err)
	assert.Equal(t, config, jsonConfig)
	
	// 重新加载YAML配置
	yamlConfig, err := LoadConfig(yamlPath)
	assert.NoError(t, err)
	assert.Equal(t, config, yamlConfig)
}

// 测试应用配置到扫描器
func TestApplyToScanner(t *testing.T) {
	// 创建配置
	config := NewConfig()
	config.Scanner.Parallel = true
	config.Scanner.Incremental = true
	config.Scanner.ConfidenceThreshold = 0.8
	
	// 创建扫描器
	scanner := NewScanner()
	
	// 应用配置
	config.ApplyToScanner(scanner)
	
	// 检查扫描器设置
	assert.True(t, scanner.IsParallel())
	assert.True(t, scanner.IsIncremental())
	assert.Equal(t, 0.8, scanner.confidenceThreshold)
} 