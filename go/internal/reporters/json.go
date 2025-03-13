package reporters

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/re-movery/re-movery/internal/core"
)

// JSONReporter is a reporter that generates JSON reports
type JSONReporter struct{}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

// GenerateReport generates a report
func (r *JSONReporter) GenerateReport(data core.ReportData, outputPath string) error {
	// Create output directory if it doesn't exist
	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Marshal data to JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return err
	}

	return nil
} 