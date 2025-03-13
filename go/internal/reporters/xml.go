package reporters

import (
	"encoding/xml"
	"os"
	"path/filepath"

	"github.com/re-movery/re-movery/internal/core"
)

// XMLReporter is a reporter that generates XML reports
type XMLReporter struct{}

// NewXMLReporter creates a new XML reporter
func NewXMLReporter() *XMLReporter {
	return &XMLReporter{}
}

// XMLReportData is the XML representation of the report data
type XMLReportData struct {
	XMLName   xml.Name        `xml:"report"`
	Title     string          `xml:"title"`
	Timestamp string          `xml:"timestamp"`
	Summary   XMLSummary      `xml:"summary"`
	Results   []XMLFileResult `xml:"results>file"`
}

// XMLSummary is the XML representation of the summary
type XMLSummary struct {
	TotalFiles int `xml:"totalFiles,attr"`
	High       int `xml:"high,attr"`
	Medium     int `xml:"medium,attr"`
	Low        int `xml:"low,attr"`
}

// XMLFileResult is the XML representation of a file result
type XMLFileResult struct {
	Path    string      `xml:"path,attr"`
	Matches []XMLMatch  `xml:"match"`
}

// XMLMatch is the XML representation of a match
type XMLMatch struct {
	ID          string  `xml:"id,attr"`
	Name        string  `xml:"name"`
	Severity    string  `xml:"severity"`
	Description string  `xml:"description"`
	LineNumber  int     `xml:"lineNumber"`
	MatchedCode string  `xml:"matchedCode"`
	Confidence  float64 `xml:"confidence"`
}

// GenerateReport generates a report
func (r *XMLReporter) GenerateReport(data core.ReportData, outputPath string) error {
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

	// Convert data to XML format
	xmlData := r.convertToXML(data)

	// Write XML header
	file.WriteString(xml.Header)

	// Marshal data to XML
	encoder := xml.NewEncoder(file)
	encoder.Indent("", "  ")
	if err := encoder.Encode(xmlData); err != nil {
		return err
	}

	return nil
}

// convertToXML converts the report data to XML format
func (r *XMLReporter) convertToXML(data core.ReportData) XMLReportData {
	xmlData := XMLReportData{
		Title:     data.Title,
		Timestamp: data.Timestamp,
		Summary: XMLSummary{
			TotalFiles: data.Summary.TotalFiles,
			High:       data.Summary.High,
			Medium:     data.Summary.Medium,
			Low:        data.Summary.Low,
		},
		Results: []XMLFileResult{},
	}

	// Convert results
	for filePath, matches := range data.Results {
		fileResult := XMLFileResult{
			Path:    filePath,
			Matches: []XMLMatch{},
		}

		for _, match := range matches {
			xmlMatch := XMLMatch{
				ID:          match.Signature.ID,
				Name:        match.Signature.Name,
				Severity:    match.Signature.Severity,
				Description: match.Signature.Description,
				LineNumber:  match.LineNumber,
				MatchedCode: match.MatchedCode,
				Confidence:  match.Confidence,
			}
			fileResult.Matches = append(fileResult.Matches, xmlMatch)
		}

		xmlData.Results = append(xmlData.Results, fileResult)
	}

	return xmlData
} 