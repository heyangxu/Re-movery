package reporters

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/re-movery/re-movery/internal/core"
)

// HTMLReporter is a reporter that generates HTML reports
type HTMLReporter struct{}

// NewHTMLReporter creates a new HTML reporter
func NewHTMLReporter() *HTMLReporter {
	return &HTMLReporter{}
}

// GenerateReport generates a report
func (r *HTMLReporter) GenerateReport(data core.ReportData, outputPath string) error {
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

	// Process data for the template
	processedData := r.processData(data)

	// Parse template
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"mul": func(a, b float64) float64 {
			return a * b
		},
	}).Parse(htmlTemplate)
	if err != nil {
		return err
	}

	// Execute template
	if err := tmpl.Execute(file, processedData); err != nil {
		return err
	}

	return nil
}

// processData processes the report data for the template
func (r *HTMLReporter) processData(data core.ReportData) map[string]interface{} {
	// Count vulnerabilities by type
	vulnCounts := make(map[string]int)
	for _, matches := range data.Results {
		for _, match := range matches {
			vulnCounts[match.Signature.Name]++
		}
	}

	// Sort vulnerabilities by count
	type vulnCount struct {
		Name  string
		Count int
	}
	vulnCountList := []vulnCount{}
	for name, count := range vulnCounts {
		vulnCountList = append(vulnCountList, vulnCount{Name: name, Count: count})
	}
	sort.Slice(vulnCountList, func(i, j int) bool {
		return vulnCountList[i].Count > vulnCountList[j].Count
	})

	// Get top 10 vulnerabilities
	topVulns := vulnCountList
	if len(topVulns) > 10 {
		topVulns = topVulns[:10]
	}

	// Prepare data for the template
	processedData := map[string]interface{}{
		"Title":     data.Title,
		"Timestamp": data.Timestamp,
		"Results":   data.Results,
		"Summary":   data.Summary,
		"TopVulnerabilities": map[string]interface{}{
			"Labels": func() []string {
				labels := []string{}
				for _, v := range topVulns {
					labels = append(labels, v.Name)
				}
				return labels
			}(),
			"Data": func() []int {
				counts := []int{}
				for _, v := range topVulns {
					counts = append(counts, v.Count)
				}
				return counts
			}(),
		},
	}

	return processedData
}

// htmlTemplate is the HTML template for the report
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ .Title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3, h4 {
            color: #2c3e50;
        }
        .summary {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .summary-item {
            display: inline-block;
            margin-right: 20px;
            padding: 10px;
            border-radius: 5px;
            text-align: center;
        }
        .high {
            background-color: #f8d7da;
            color: #721c24;
        }
        .medium {
            background-color: #fff3cd;
            color: #856404;
        }
        .low {
            background-color: #d1ecf1;
            color: #0c5460;
        }
        .file-item {
            margin-bottom: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
            overflow: hidden;
        }
        .file-header {
            background-color: #f1f1f1;
            padding: 10px;
            cursor: pointer;
        }
        .file-content {
            padding: 10px;
        }
        .match-item {
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 5px;
        }
        .match-code {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            white-space: pre-wrap;
            margin-top: 10px;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 0.8em;
            color: #777;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .chart-container {
            width: 100%;
            height: 300px;
            margin-bottom: 20px;
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>{{ .Title }}</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <div class="summary-item high">
            <h3>{{ .Summary.High }}</h3>
            <p>High Severity</p>
        </div>
        <div class="summary-item medium">
            <h3>{{ .Summary.Medium }}</h3>
            <p>Medium Severity</p>
        </div>
        <div class="summary-item low">
            <h3>{{ .Summary.Low }}</h3>
            <p>Low Severity</p>
        </div>
        <div class="summary-item">
            <h3>{{ .Summary.TotalFiles }}</h3>
            <p>Files Scanned</p>
        </div>
    </div>
    
    <div class="chart-container">
        <canvas id="vulnerabilitiesChart"></canvas>
    </div>
    
    <h2>Top Vulnerabilities</h2>
    <div class="chart-container">
        <canvas id="topVulnerabilitiesChart"></canvas>
    </div>
    
    <h2>Detailed Results</h2>
    {{range $file, $matches := .Results}}
    <div class="file-item">
        <div class="file-header" onclick="toggleFileContent(this)">
            <h3>{{$file}}</h3>
            <span>{{len $matches}} issues found</span>
        </div>
        <div class="file-content">
            <table>
                <thead>
                    <tr>
                        <th>Line</th>
                        <th>Severity</th>
                        <th>Issue</th>
                        <th>Confidence</th>
                    </tr>
                </thead>
                <tbody>
                    {{range $match := $matches}}
                    <tr class="match-item {{$match.Signature.Severity}}">
                        <td>{{$match.LineNumber}}</td>
                        <td>{{$match.Signature.Severity}}</td>
                        <td>
                            <strong>{{$match.Signature.Name}}</strong>
                            <p>{{$match.Signature.Description}}</p>
                            <div class="match-code">{{$match.MatchedCode}}</div>
                        </td>
                        <td>{{printf "%.0f%%" (mul $match.Confidence 100)}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
    {{end}}
    
    <div class="footer">
        <p>Report generated by Re-movery on {{.Timestamp}}</p>
    </div>
    
    <script>
        function toggleFileContent(header) {
            const content = header.nextElementSibling;
            content.style.display = content.style.display === 'none' ? 'block' : 'none';
        }
        
        // Initialize all file contents as hidden
        document.addEventListener('DOMContentLoaded', function() {
            const fileContents = document.querySelectorAll('.file-content');
            fileContents.forEach(content => {
                content.style.display = 'none';
            });
            
            // Create severity distribution chart
            const severityCtx = document.getElementById('vulnerabilitiesChart').getContext('2d');
            new Chart(severityCtx, {
                type: 'pie',
                data: {
                    labels: ['High', 'Medium', 'Low'],
                    datasets: [{
                        data: [{{.Summary.High}}, {{.Summary.Medium}}, {{.Summary.Low}}],
                        backgroundColor: ['#f8d7da', '#fff3cd', '#d1ecf1'],
                        borderColor: ['#721c24', '#856404', '#0c5460'],
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: {
                            position: 'top',
                        },
                        title: {
                            display: true,
                            text: 'Severity Distribution'
                        }
                    }
                }
            });
            
            // Create top vulnerabilities chart
            const topVulnCtx = document.getElementById('topVulnerabilitiesChart').getContext('2d');
            new Chart(topVulnCtx, {
                type: 'bar',
                data: {
                    labels: {{.TopVulnerabilities.Labels}},
                    datasets: [{
                        label: 'Occurrences',
                        data: {{.TopVulnerabilities.Data}},
                        backgroundColor: 'rgba(54, 162, 235, 0.2)',
                        borderColor: 'rgba(54, 162, 235, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                precision: 0
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        },
                        title: {
                            display: true,
                            text: 'Top Vulnerabilities'
                        }
                    }
                }
            });
        });
    </script>
</body>
</html>` 