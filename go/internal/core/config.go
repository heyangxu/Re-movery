package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 表示应用程序配置
type Config struct {
	Scanner ScannerConfig `json:"scanner" yaml:"scanner"`
	Web     WebConfig     `json:"web" yaml:"web"`
	Server  ServerConfig  `json:"server" yaml:"server"`
}

// ScannerConfig 表示扫描器配置
type ScannerConfig struct {
	Parallel            bool    `json:"parallel" yaml:"parallel"`
	Incremental         bool    `json:"incremental" yaml:"incremental"`
	ConfidenceThreshold float64 `json:"confidenceThreshold" yaml:"confidenceThreshold"`
	ExcludePatterns     []string `json:"excludePatterns" yaml:"excludePatterns"`
}

// WebConfig 表示Web界面配置
type WebConfig struct {
	Host  string `json:"host" yaml:"host"`
	Port  int    `json:"port" yaml:"port"`
	Debug bool   `json:"debug" yaml:"debug"`
}

// ServerConfig 表示API服务器配置
type ServerConfig struct {
	Host  string `json:"host" yaml:"host"`
	Port  int    `json:"port" yaml:"port"`
	Debug bool   `json:"debug" yaml:"debug"`
}

// NewConfig 创建一个新的配置对象，使用默认值
func NewConfig() *Config {
	return &Config{
		Scanner: ScannerConfig{
			Parallel:            false,
			Incremental:         false,
			ConfidenceThreshold: 0.7,
			ExcludePatterns:     []string{},
		},
		Web: WebConfig{
			Host:  "localhost",
			Port:  8080,
			Debug: false,
		},
		Server: ServerConfig{
			Host:  "localhost",
			Port:  8081,
			Debug: false,
		},
	}
}

// LoadConfig 从文件加载配置
func LoadConfig(configPath string) (*Config, error) {
	// 如果未指定配置文件，则使用默认配置
	if configPath == "" {
		return NewConfig(), nil
	}

	// 检查文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("配置文件不存在: %s", configPath)
	}

	// 读取文件内容
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	// 根据文件扩展名解析配置
	config := NewConfig()
	ext := strings.ToLower(filepath.Ext(configPath))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, err
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("不支持的配置文件格式: %s", ext)
	}

	return config, nil
}

// SaveConfig 将配置保存到文件
func SaveConfig(config *Config, configPath string) error {
	// 创建输出目录（如果不存在）
	outputDir := filepath.Dir(configPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	// 根据文件扩展名序列化配置
	var data []byte
	var err error
	ext := strings.ToLower(filepath.Ext(configPath))
	switch ext {
	case ".json":
		data, err = json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}
	case ".yaml", ".yml":
		data, err = yaml.Marshal(config)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("不支持的配置文件格式: %s", ext)
	}

	// 写入文件
	return ioutil.WriteFile(configPath, data, 0644)
}

// ApplyToScanner 将配置应用到扫描器
func (c *Config) ApplyToScanner(scanner *Scanner) {
	scanner.SetParallel(c.Scanner.Parallel)
	scanner.SetIncremental(c.Scanner.Incremental)
	scanner.SetConfidenceThreshold(c.Scanner.ConfidenceThreshold)
} 