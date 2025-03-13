package core

import (
	"time"
)

// Signature represents a vulnerability signature
type Signature struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Severity     string   `json:"severity"`
	Description  string   `json:"description"`
	CodePatterns []string `json:"codePatterns"`
	References   []string `json:"references"`
}

// Match represents a vulnerability match
type Match struct {
	Signature   Signature `json:"signature"`
	FilePath    string    `json:"filePath"`
	LineNumber  int       `json:"lineNumber"`
	MatchedCode string    `json:"matchedCode"`
	Confidence  float64   `json:"confidence"`
}

// Summary represents a summary of scan results
type Summary struct {
	TotalFiles int            `json:"totalFiles"`
	High       int            `json:"high"`
	Medium     int            `json:"medium"`
	Low        int            `json:"low"`
	Vulnerabilities map[string]int `json:"vulnerabilities"`
}

// ReportData represents data for a report
type ReportData struct {
	Title     string                `json:"title"`
	Timestamp string                `json:"timestamp"`
	Results   map[string][]Match    `json:"results"`
	Summary   Summary               `json:"summary"`
}

// Reporter is an interface for report generators
type Reporter interface {
	GenerateReport(data ReportData, outputPath string) error
}

// Detector is an interface for vulnerability detectors
type Detector interface {
	Name() string
	SupportedLanguages() []string
	DetectFile(filePath string) ([]Match, error)
	DetectCode(code string, filePath string) ([]Match, error)
}

// GenerateSummary generates a summary from scan results
func GenerateSummary(results map[string][]Match) Summary {
	summary := Summary{
		TotalFiles: len(results),
		Vulnerabilities: make(map[string]int),
	}

	for _, matches := range results {
		for _, match := range matches {
			switch match.Signature.Severity {
			case "high":
				summary.High++
			case "medium":
				summary.Medium++
			case "low":
				summary.Low++
			}

			// Count vulnerabilities by name
			summary.Vulnerabilities[match.Signature.Name]++
		}
	}

	return summary
} 