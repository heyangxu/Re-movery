package main

import (
    "flag"
    "fmt"
    "os"
    "path/filepath"
    "time"

    "github.com/heyangxu/re-movery/internal/analyzers"
    "github.com/heyangxu/re-movery/internal/config"
    "github.com/heyangxu/re-movery/internal/detectors"
    "github.com/heyangxu/re-movery/internal/reporters"
    "github.com/heyangxu/re-movery/internal/utils"
)

var (
    configFile  string
    targetPath  string
    outputDir   string
    verbose     bool
    maxMemoryGB float64
)

func init() {
    flag.StringVar(&configFile, "config", "config.json", "Path to configuration file")
    flag.StringVar(&targetPath, "target", ".", "Path to target directory or file")
    flag.StringVar(&outputDir, "output", "reports", "Path to output directory")
    flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
    flag.Float64Var(&maxMemoryGB, "memory", 8.0, "Maximum memory usage in GB")
}

func main() {
    flag.Parse()

    // Initialize logger
    utils.SetVerbosity(verbose)
    logger := utils.GetLogger()

    // Load configuration
    cfg, err := config.LoadConfig(configFile)
    if err != nil {
        logger.Fatalf("Failed to load configuration: %v", err)
    }

    // Initialize memory monitor
    memMonitor := utils.NewMemoryMonitor(maxMemoryGB, 5*time.Second)
    memMonitor.Start()
    defer memMonitor.Stop()

    // Initialize worker pool
    workerPool := utils.NewWorkerPool(cfg.Processing.NumWorkers, 100)
    workerPool.Start()
    defer workerPool.Stop()

    // Initialize vulnerability detector
    detector := detectors.NewVulnerabilityDetector()
    if err := detector.LoadSignatures("signatures.json"); err != nil {
        logger.Fatalf("Failed to load vulnerability signatures: %v", err)
    }

    // Initialize language analyzer
    analyzer := analyzers.NewGoAnalyzer()

    // Initialize HTML reporter
    reporter := reporters.NewHTMLReporter(
        filepath.Join("web", "templates", "report.html"),
        outputDir,
    )

    // Process target path
    logger.Infof("Processing target: %s", targetPath)
    matches, err := detector.DetectDirectory(targetPath)
    if err != nil {
        logger.Fatalf("Failed to detect vulnerabilities: %v", err)
    }

    // Generate report
    logger.Info("Generating report...")
    if err := reporter.GenerateReport(matches); err != nil {
        logger.Fatalf("Failed to generate report: %v", err)
    }

    logger.Infof("Found %d potential vulnerabilities", len(matches))
    logger.Infof("Report generated at: %s", filepath.Join(outputDir, "report.html"))
} 