package detectors

import (
	"bufio"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/re-movery/re-movery/internal/core"
)

// JavaScriptDetector is a detector for JavaScript code
type JavaScriptDetector struct {
	signatures []core.Signature
}

// NewJavaScriptDetector creates a new JavaScript detector
func NewJavaScriptDetector() *JavaScriptDetector {
	detector := &JavaScriptDetector{}
	detector.loadSignatures()
	return detector
}

// Name returns the name of the detector
func (d *JavaScriptDetector) Name() string {
	return "javascript"
}

// SupportedLanguages returns the list of supported languages
func (d *JavaScriptDetector) SupportedLanguages() []string {
	return []string{"javascript", "js", "jsx", "ts", "tsx"}
}

// DetectFile detects vulnerabilities in a file
func (d *JavaScriptDetector) DetectFile(filePath string) ([]core.Match, error) {
	// Check if file is a JavaScript file
	ext := filepath.Ext(filePath)
	if ext != ".js" && ext != ".jsx" && ext != ".ts" && ext != ".tsx" {
		return nil, nil
	}

	// Read file
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	return d.DetectCode(string(content), filePath)
}

// DetectCode detects vulnerabilities in code
func (d *JavaScriptDetector) DetectCode(code string, filePath string) ([]core.Match, error) {
	matches := []core.Match{}

	// Scan code line by line
	scanner := bufio.NewScanner(strings.NewReader(code))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Check each signature
		for _, signature := range d.signatures {
			for _, pattern := range signature.CodePatterns {
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}

				if re.MatchString(line) {
					match := core.Match{
						Signature:   signature,
						FilePath:    filePath,
						LineNumber:  lineNumber,
						MatchedCode: line,
						Confidence:  d.calculateConfidence(line, pattern),
					}
					matches = append(matches, match)
				}
			}
		}
	}

	// Perform additional JavaScript-specific checks
	matches = append(matches, d.checkJavaScriptSpecificIssues(code, filePath)...)

	return matches, nil
}

// loadSignatures loads the signatures for JavaScript code
func (d *JavaScriptDetector) loadSignatures() {
	d.signatures = []core.Signature{
		{
			ID:          "JS001",
			Name:        "Dangerous eval() usage",
			Severity:    "high",
			Description: "Using eval() can execute arbitrary code and is a security risk",
			CodePatterns: []string{
				`eval\s*\([^)]*\)`,
			},
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval",
			},
		},
		{
			ID:          "JS002",
			Name:        "Dangerous Function() constructor",
			Severity:    "high",
			Description: "Using Function() constructor can execute arbitrary code and is a security risk",
			CodePatterns: []string{
				`new\s+Function\s*\([^)]*\)`,
				`Function\s*\([^)]*\)`,
			},
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function",
			},
		},
		{
			ID:          "JS003",
			Name:        "DOM-based XSS risk",
			Severity:    "high",
			Description: "Manipulating innerHTML with user input can lead to XSS",
			CodePatterns: []string{
				`\.innerHTML\s*=`,
				`\.outerHTML\s*=`,
				`document\.write\s*\(`,
				`document\.writeln\s*\(`,
			},
			References: []string{
				"https://owasp.org/www-community/attacks/xss/",
			},
		},
		{
			ID:          "JS004",
			Name:        "Insecure random number generation",
			Severity:    "medium",
			Description: "Using Math.random() for security purposes is not recommended",
			CodePatterns: []string{
				`Math\.random\s*\(\)`,
			},
			References: []string{
				"https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random",
			},
		},
		{
			ID:          "JS005",
			Name:        "Hardcoded credentials",
			Severity:    "high",
			Description: "Hardcoded credentials are a security risk",
			CodePatterns: []string{
				`password\s*=\s*['\"][^'\"]{3,}['\"]`,
				`passwd\s*=\s*['\"][^'\"]{3,}['\"]`,
				`pwd\s*=\s*['\"][^'\"]{3,}['\"]`,
				`secret\s*=\s*['\"][^'\"]{3,}['\"]`,
				`apiKey\s*=\s*['\"][^'\"]{3,}['\"]`,
			},
			References: []string{
				"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
			},
		},
		{
			ID:          "JS006",
			Name:        "Insecure HTTP protocol",
			Severity:    "medium",
			Description: "Using HTTP instead of HTTPS can expose data to eavesdropping",
			CodePatterns: []string{
				`http:\/\/[^'\"]*['\"]`,
			},
			References: []string{
				"https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
			},
		},
		{
			ID:          "JS007",
			Name:        "Potential prototype pollution",
			Severity:    "high",
			Description: "Modifying Object.prototype can lead to prototype pollution vulnerabilities",
			CodePatterns: []string{
				`Object\.prototype\.[^=]+=`,
				`__proto__\.[^=]+=`,
			},
			References: []string{
				"https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf",
			},
		},
		{
			ID:          "JS008",
			Name:        "Insecure JWT verification",
			Severity:    "high",
			Description: "Not verifying JWT signatures can lead to authentication bypass",
			CodePatterns: []string{
				`jwt\.verify\s*\([^,]*,\s*['\"]?none['\"]?[^)]*\)`,
			},
			References: []string{
				"https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/",
			},
		},
		{
			ID:          "JS009",
			Name:        "Insecure cookie settings",
			Severity:    "medium",
			Description: "Cookies without secure or httpOnly flags can be vulnerable to theft",
			CodePatterns: []string{
				`document\.cookie\s*=\s*[^;]*(?!secure|httpOnly)`,
				`\.cookie\s*\([^)]*(?!secure|httpOnly)[^)]*\)`,
			},
			References: []string{
				"https://owasp.org/www-community/controls/SecureCookieAttribute",
			},
		},
		{
			ID:          "JS010",
			Name:        "Debug mode enabled",
			Severity:    "medium",
			Description: "Running applications in debug mode can expose sensitive information",
			CodePatterns: []string{
				`debug\s*:\s*true`,
				`debugMode\s*=\s*true`,
			},
			References: []string{
				"https://expressjs.com/en/advanced/best-practice-security.html",
			},
		},
	}
}

// calculateConfidence calculates the confidence of a match
func (d *JavaScriptDetector) calculateConfidence(matchedCode string, pattern string) float64 {
	// Base confidence
	confidence := 0.8

	// Adjust based on match length
	if len(matchedCode) > 10 {
		confidence += 0.05
	}

	// Adjust based on context
	if strings.Contains(matchedCode, "import") || strings.Contains(matchedCode, "require") {
		confidence += 0.05
	}

	// Adjust based on pattern specificity
	if len(pattern) > 20 {
		confidence += 0.05
	}

	// Adjust based on function call parameters
	if strings.Contains(matchedCode, "(") && strings.Contains(matchedCode, ")") {
		confidence += 0.05
	}

	// Ensure confidence is between 0 and 1
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// checkJavaScriptSpecificIssues performs additional JavaScript-specific checks
func (d *JavaScriptDetector) checkJavaScriptSpecificIssues(code string, filePath string) []core.Match {
	matches := []core.Match{}

	// Check for use of console.log in production code
	consoleLogRe := regexp.MustCompile(`console\.log\s*\(`)
	consoleLogMatches := consoleLogRe.FindAllStringIndex(code, -1)
	for _, match := range consoleLogMatches {
		// Count line number
		lineNumber := 1 + strings.Count(code[:match[0]], "\n")
		matchedCode := code[match[0]:match[1]] + "...)"

		matches = append(matches, core.Match{
			Signature: core.Signature{
				ID:          "JS011",
				Name:        "Console logging in production",
				Severity:    "low",
				Description: "Console logging should be removed from production code",
				CodePatterns: []string{
					`console\.log\s*\(`,
				},
			},
			FilePath:    filePath,
			LineNumber:  lineNumber,
			MatchedCode: matchedCode,
			Confidence:  0.7,
		})
	}

	// Check for use of alert in production code
	alertRe := regexp.MustCompile(`alert\s*\(`)
	alertMatches := alertRe.FindAllStringIndex(code, -1)
	for _, match := range alertMatches {
		// Count line number
		lineNumber := 1 + strings.Count(code[:match[0]], "\n")
		matchedCode := code[match[0]:match[1]] + "...)"

		matches = append(matches, core.Match{
			Signature: core.Signature{
				ID:          "JS012",
				Name:        "Alert in production",
				Severity:    "low",
				Description: "Alert dialogs should be removed from production code",
				CodePatterns: []string{
					`alert\s*\(`,
				},
			},
			FilePath:    filePath,
			LineNumber:  lineNumber,
			MatchedCode: matchedCode,
			Confidence:  0.7,
		})
	}

	return matches
} 