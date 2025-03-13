package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/re-movery/re-movery/internal/core"
	"github.com/re-movery/re-movery/internal/detectors"
	"github.com/re-movery/re-movery/internal/reporters"
	"github.com/spf13/cobra"
)

var (
	scanFile       string
	scanDir        string
	excludePattern string
	outputFile     string
	reportFormat   string
	parallel       bool
	incremental    bool
	confidence     float64
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan files or directories for security vulnerabilities",
	Long: `Scan files or directories for security vulnerabilities.
Examples:
  re-movery scan --file path/to/file.py
  re-movery scan --dir path/to/directory --exclude "node_modules,*.min.js"
  re-movery scan --dir path/to/directory --output report.html --format html`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create scanner
		scanner := core.NewScanner()
		
		// Register detectors
		scanner.RegisterDetector(detectors.NewPythonDetector())
		scanner.RegisterDetector(detectors.NewJavaScriptDetector())
		
		// Set scanner options
		scanner.SetParallel(parallel)
		scanner.SetIncremental(incremental)
		scanner.SetConfidenceThreshold(confidence)
		
		// Parse exclude patterns
		var excludePatterns []string
		if excludePattern != "" {
			excludePatterns = strings.Split(excludePattern, ",")
			for i, pattern := range excludePatterns {
				excludePatterns[i] = strings.TrimSpace(pattern)
			}
		}
		
		// Scan file or directory
		var results map[string][]core.Match
		var err error
		
		if scanFile != "" {
			// Check if file exists
			if _, err := os.Stat(scanFile); os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Error: File does not exist: %s\n", scanFile)
				os.Exit(1)
			}
			
			// Scan file
			matches, err := scanner.ScanFile(scanFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error scanning file: %v\n", err)
				os.Exit(1)
			}
			
			results = map[string][]core.Match{
				scanFile: matches,
			}
		} else if scanDir != "" {
			// Check if directory exists
			if _, err := os.Stat(scanDir); os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Error: Directory does not exist: %s\n", scanDir)
				os.Exit(1)
			}
			
			// Scan directory
			results, err = scanner.ScanDirectory(scanDir, excludePatterns)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error scanning directory: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Error: Please specify a file or directory to scan\n")
			cmd.Help()
			os.Exit(1)
		}
		
		// Generate summary
		summary := core.GenerateSummary(results)
		
		// Print summary to console
		fmt.Printf("Scan completed in %s\n", time.Now().Format(time.RFC3339))
		fmt.Printf("Files scanned: %d\n", summary.TotalFiles)
		fmt.Printf("Issues found: %d (High: %d, Medium: %d, Low: %d)\n",
			summary.High+summary.Medium+summary.Low, summary.High, summary.Medium, summary.Low)
		
		// Generate report if output file is specified
		if outputFile != "" {
			// Create report data
			reportData := core.ReportData{
				Title:     "Re-movery Security Scan Report",
				Timestamp: time.Now().Format(time.RFC3339),
				Results:   results,
				Summary:   summary,
			}
			
			// Determine report format
			if reportFormat == "" {
				// Try to determine format from file extension
				ext := strings.ToLower(filepath.Ext(outputFile))
				switch ext {
				case ".html":
					reportFormat = "html"
				case ".json":
					reportFormat = "json"
				case ".xml":
					reportFormat = "xml"
				default:
					reportFormat = "html" // Default to HTML
				}
			}
			
			// Generate report
			var reporter core.Reporter
			switch strings.ToLower(reportFormat) {
			case "html":
				reporter = reporters.NewHTMLReporter()
			case "json":
				reporter = reporters.NewJSONReporter()
			case "xml":
				reporter = reporters.NewXMLReporter()
			default:
				fmt.Fprintf(os.Stderr, "Error: Unsupported report format: %s\n", reportFormat)
				os.Exit(1)
			}
			
			if err := reporter.GenerateReport(reportData, outputFile); err != nil {
				fmt.Fprintf(os.Stderr, "Error generating report: %v\n", err)
				os.Exit(1)
			}
			
			fmt.Printf("Report generated: %s\n", outputFile)
		}
	},
}

func init() {
	// Add flags
	scanCmd.Flags().StringVar(&scanFile, "file", "", "File to scan")
	scanCmd.Flags().StringVar(&scanDir, "dir", "", "Directory to scan")
	scanCmd.Flags().StringVar(&excludePattern, "exclude", "", "Patterns to exclude (comma separated)")
	scanCmd.Flags().StringVar(&outputFile, "output", "", "Output file for the report")
	scanCmd.Flags().StringVar(&reportFormat, "format", "", "Report format (html, json, xml)")
	scanCmd.Flags().BoolVar(&parallel, "parallel", false, "Enable parallel processing")
	scanCmd.Flags().BoolVar(&incremental, "incremental", false, "Enable incremental scanning")
	scanCmd.Flags().Float64Var(&confidence, "confidence", 0.7, "Confidence threshold (0.0-1.0)")
} 