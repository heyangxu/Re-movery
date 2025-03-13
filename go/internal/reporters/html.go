package reporters

import (
    "html/template"
    "os"
    "path/filepath"
    "time"

    "github.com/go-echarts/go-echarts/v2/charts"
    "github.com/go-echarts/go-echarts/v2/opts"
    "github.com/heyangxu/re-movery/internal/detectors"
)

// HTMLReporter generates HTML reports
type HTMLReporter struct {
    templatePath string
    outputDir   string
}

// ReportData represents the data for the HTML report
type ReportData struct {
    GeneratedAt     time.Time
    TotalFiles      int
    TotalMatches    int
    Vulnerabilities []detectors.VulnerabilityMatch
    SeverityChart   *charts.Pie
    TypeChart       *charts.Bar
}

// NewHTMLReporter creates a new HTML reporter
func NewHTMLReporter(templatePath, outputDir string) *HTMLReporter {
    return &HTMLReporter{
        templatePath: templatePath,
        outputDir:   outputDir,
    }
}

// GenerateReport generates an HTML report from vulnerability matches
func (hr *HTMLReporter) GenerateReport(matches []detectors.VulnerabilityMatch) error {
    // Create output directory if it doesn't exist
    if err := os.MkdirAll(hr.outputDir, 0755); err != nil {
        return err
    }

    // Prepare report data
    data := hr.prepareReportData(matches)

    // Generate charts
    hr.generateCharts(data)

    // Parse template
    tmpl, err := template.ParseFiles(hr.templatePath)
    if err != nil {
        return err
    }

    // Create output file
    outputFile := filepath.Join(hr.outputDir, "report.html")
    f, err := os.Create(outputFile)
    if err != nil {
        return err
    }
    defer f.Close()

    // Execute template
    return tmpl.Execute(f, data)
}

// prepareReportData prepares data for the report
func (hr *HTMLReporter) prepareReportData(matches []detectors.VulnerabilityMatch) *ReportData {
    data := &ReportData{
        GeneratedAt:     time.Now(),
        TotalMatches:    len(matches),
        Vulnerabilities: matches,
    }

    // Count unique files
    files := make(map[string]bool)
    for _, match := range matches {
        files[match.File] = true
    }
    data.TotalFiles = len(files)

    return data
}

// generateCharts generates charts for the report
func (hr *HTMLReporter) generateCharts(data *ReportData) {
    // Generate severity distribution pie chart
    pie := charts.NewPie()
    pie.SetGlobalOptions(
        charts.WithTitleOpts(opts.Title{
            Title: "Vulnerability Severity Distribution",
        }),
    )

    severityCount := make(map[string]int)
    for _, match := range data.Vulnerabilities {
        severityCount[match.Signature.Severity]++
    }

    var pieItems []opts.PieData
    for severity, count := range severityCount {
        pieItems = append(pieItems, opts.PieData{
            Name:  severity,
            Value: count,
        })
    }
    pie.AddSeries("Severity", pieItems)
    data.SeverityChart = pie

    // Generate vulnerability type bar chart
    bar := charts.NewBar()
    bar.SetGlobalOptions(
        charts.WithTitleOpts(opts.Title{
            Title: "Vulnerability Types",
        }),
    )

    typeCount := make(map[string]int)
    for _, match := range data.Vulnerabilities {
        typeCount[match.Signature.Name]++
    }

    var xAxis []string
    var yAxis []int
    for vulnType, count := range typeCount {
        xAxis = append(xAxis, vulnType)
        yAxis = append(yAxis, count)
    }

    bar.SetXAxis(xAxis).AddSeries("Count", generateBarItems(yAxis))
    data.TypeChart = bar
}

// generateBarItems generates bar chart items
func generateBarItems(data []int) []opts.BarData {
    items := make([]opts.BarData, 0)
    for _, d := range data {
        items = append(items, opts.BarData{Value: d})
    }
    return items
} 