package config

import (
    "github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
    Processing ProcessingConfig `mapstructure:"processing"`
    Detector   DetectorConfig   `mapstructure:"detector"`
    Logging    LoggingConfig    `mapstructure:"logging"`
    Security   SecurityConfig   `mapstructure:"security"`
}

// ProcessingConfig contains processing-related configuration
type ProcessingConfig struct {
    NumWorkers    int      `mapstructure:"num_workers"`
    MaxMemoryGB   float64  `mapstructure:"max_memory_gb"`
    ChunkSizeMB   int      `mapstructure:"chunk_size_mb"`
    EnableCache   bool     `mapstructure:"enable_cache"`
    CacheSize     int      `mapstructure:"cache_size"`
    Languages     []string `mapstructure:"languages"`
}

// DetectorConfig contains detector-related configuration
type DetectorConfig struct {
    MinSimilarity     float64  `mapstructure:"min_similarity"`
    EditDistance      int      `mapstructure:"edit_distance"`
    ContextLines      int      `mapstructure:"context_lines"`
    ASTDepth         int      `mapstructure:"ast_depth"`
    CFGNodes         int      `mapstructure:"cfg_nodes"`
    ReportFormat     []string `mapstructure:"report_format"`
    ExcludePatterns  []string `mapstructure:"exclude_patterns"`
}

// LoggingConfig contains logging-related configuration
type LoggingConfig struct {
    Level           string `mapstructure:"level"`
    File            string `mapstructure:"file"`
    Format          string `mapstructure:"format"`
    EnableProfiling bool   `mapstructure:"enable_profiling"`
    ShowProgress    bool   `mapstructure:"show_progress"`
}

// SecurityConfig contains security-related configuration
type SecurityConfig struct {
    MaxFileSizeMB     int      `mapstructure:"max_file_size_mb"`
    AllowedSchemes    []string `mapstructure:"allowed_schemes"`
    EnableSandbox     bool     `mapstructure:"enable_sandbox"`
    RequireAuth       bool     `mapstructure:"require_auth"`
    RateLimitPerHour  int      `mapstructure:"rate_limit_per_hour"`
}

// LoadConfig loads the configuration from file
func LoadConfig(configFile string) (*Config, error) {
    viper.SetConfigFile(configFile)
    viper.SetConfigType("json")

    if err := viper.ReadInConfig(); err != nil {
        return nil, err
    }

    var config Config
    if err := viper.Unmarshal(&config); err != nil {
        return nil, err
    }

    return &config, nil
}

// SetDefaults sets default configuration values
func SetDefaults() {
    viper.SetDefault("processing.num_workers", 4)
    viper.SetDefault("processing.max_memory_gb", 8)
    viper.SetDefault("processing.chunk_size_mb", 1)
    viper.SetDefault("processing.enable_cache", true)
    viper.SetDefault("processing.cache_size", 1000)
    viper.SetDefault("processing.languages", []string{"go", "java", "python", "javascript"})

    viper.SetDefault("detector.min_similarity", 0.8)
    viper.SetDefault("detector.edit_distance", 3)
    viper.SetDefault("detector.context_lines", 3)
    viper.SetDefault("detector.ast_depth", 5)
    viper.SetDefault("detector.cfg_nodes", 100)
    viper.SetDefault("detector.report_format", []string{"html", "json"})

    viper.SetDefault("logging.level", "info")
    viper.SetDefault("logging.format", "text")
    viper.SetDefault("logging.enable_profiling", false)
    viper.SetDefault("logging.show_progress", true)

    viper.SetDefault("security.max_file_size_mb", 10)
    viper.SetDefault("security.enable_sandbox", true)
    viper.SetDefault("security.require_auth", false)
    viper.SetDefault("security.rate_limit_per_hour", 1000)
} 