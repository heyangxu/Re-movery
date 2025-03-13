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

// PythonDetector is a detector for Python code
type PythonDetector struct {
	signatures []core.Signature
}

// NewPythonDetector creates a new Python detector
func NewPythonDetector() *PythonDetector {
	detector := &PythonDetector{}
	detector.loadSignatures()
	return detector
}

// Name returns the name of the detector
func (d *PythonDetector) Name() string {
	return "python"
}

// SupportedLanguages returns the list of supported languages
func (d *PythonDetector) SupportedLanguages() []string {
	return []string{"python", "py"}
}

// DetectFile detects vulnerabilities in a file
func (d *PythonDetector) DetectFile(filePath string) ([]core.Match, error) {
	// Check if file is a Python file
	if filepath.Ext(filePath) != ".py" {
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
func (d *PythonDetector) DetectCode(code string, filePath string) ([]core.Match, error) {
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

	// Perform additional Python-specific checks
	matches = append(matches, d.checkPythonSpecificIssues(code, filePath)...)

	return matches, nil
}

// loadSignatures loads the signatures for Python code
func (d *PythonDetector) loadSignatures() {
	d.signatures = []core.Signature{
		{
			ID:          "PY001",
			Name:        "Dangerous eval() usage",
			Severity:    "high",
			Description: "Using eval() can execute arbitrary code and is a security risk",
			CodePatterns: []string{
				`eval\s*\([^)]*\)`,
			},
			References: []string{
				"https://docs.python.org/3/library/functions.html#eval",
			},
		},
		{
			ID:          "PY002",
			Name:        "Dangerous exec() usage",
			Severity:    "high",
			Description: "Using exec() can execute arbitrary code and is a security risk",
			CodePatterns: []string{
				`exec\s*\([^)]*\)`,
			},
			References: []string{
				"https://docs.python.org/3/library/functions.html#exec",
			},
		},
		{
			ID:          "PY003",
			Name:        "Insecure pickle usage",
			Severity:    "high",
			Description: "Using pickle with untrusted data can lead to arbitrary code execution",
			CodePatterns: []string{
				`pickle\.loads\s*\([^)]*\)`,
				`pickle\.load\s*\([^)]*\)`,
			},
			References: []string{
				"https://docs.python.org/3/library/pickle.html",
			},
		},
		{
			ID:          "PY004",
			Name:        "SQL Injection risk",
			Severity:    "high",
			Description: "String formatting in SQL queries can lead to SQL injection",
			CodePatterns: []string{
				`execute\s*\(['\"][^'\"]*%[^'\"]*['\"]`,
				`execute\s*\(['\"][^'\"]*\{\s*[^}]*\}[^'\"]*['\"]\.format`,
				`execute\s*\(['\"][^'\"]*\+[^'\"]*['\"]`,
			},
			References: []string{
				"https://owasp.org/www-community/attacks/SQL_Injection",
			},
		},
		{
			ID:          "PY005",
			Name:        "Insecure random number generation",
			Severity:    "medium",
			Description: "Using random module for security purposes is not recommended",
			CodePatterns: []string{
				`random\.(?:random|randint|choice|randrange)`,
			},
			References: []string{
				"https://docs.python.org/3/library/random.html",
			},
		},
		{
			ID:          "PY006",
			Name:        "Hardcoded credentials",
			Severity:    "high",
			Description: "Hardcoded credentials are a security risk",
			CodePatterns: []string{
				`password\s*=\s*['\"][^'\"]{3,}['\"]`,
				`passwd\s*=\s*['\"][^'\"]{3,}['\"]`,
				`pwd\s*=\s*['\"][^'\"]{3,}['\"]`,
				`secret\s*=\s*['\"][^'\"]{3,}['\"]`,
				`api_key\s*=\s*['\"][^'\"]{3,}['\"]`,
			},
			References: []string{
				"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
			},
		},
		{
			ID:          "PY007",
			Name:        "Insecure hash function",
			Severity:    "medium",
			Description: "Using weak hash functions like MD5 or SHA1",
			CodePatterns: []string{
				`hashlib\.md5`,
				`hashlib\.sha1`,
			},
			References: []string{
				"https://owasp.org/www-community/vulnerabilities/Insufficient_entropy",
			},
		},
		{
			ID:          "PY008",
			Name:        "Temporary file creation risk",
			Severity:    "medium",
			Description: "Insecure temporary file creation can lead to race conditions",
			CodePatterns: []string{
				`open\s*\(['\"][^'\"]*\/tmp[^'\"]*['\"]`,
				`tempfile\.mktemp`,
			},
			References: []string{
				"https://docs.python.org/3/library/tempfile.html",
			},
		},
		{
			ID:          "PY009",
			Name:        "Insecure deserialization",
			Severity:    "high",
			Description: "Deserializing untrusted data can lead to arbitrary code execution",
			CodePatterns: []string{
				`yaml\.load\s*\([^)]*\)`,
				`json\.loads\s*\([^)]*\)`,
			},
			References: []string{
				"https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
			},
		},
		{
			ID:          "PY010",
			Name:        "Debug mode enabled",
			Severity:    "medium",
			Description: "Running applications in debug mode can expose sensitive information",
			CodePatterns: []string{
				`debug\s*=\s*True`,
				`app\.run\s*\([^)]*debug\s*=\s*True[^)]*\)`,
			},
			References: []string{
				"https://flask.palletsprojects.com/en/2.0.x/config/#DEBUG",
			},
		},
	}
}

// calculateConfidence calculates the confidence of a match
func (d *PythonDetector) calculateConfidence(matchedCode string, pattern string) float64 {
	// Base confidence
	confidence := 0.8

	// Adjust based on match length
	if len(matchedCode) > 10 {
		confidence += 0.05
	}

	// Adjust based on context
	if strings.Contains(matchedCode, "import") {
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

// checkPythonSpecificIssues performs additional Python-specific checks
func (d *PythonDetector) checkPythonSpecificIssues(code string, filePath string) []core.Match {
	matches := []core.Match{}

	// Check for empty except blocks
	emptyExceptRe := regexp.MustCompile(`(?m)^(\s*)except(\s+\w+)?:\s*$`)
	emptyExceptMatches := emptyExceptRe.FindAllStringIndex(code, -1)
	for _, match := range emptyExceptMatches {
		// Count line number
		lineNumber := 1 + strings.Count(code[:match[0]], "\n")
		matchedCode := code[match[0]:match[1]]

		matches = append(matches, core.Match{
			Signature: core.Signature{
				ID:          "PY011",
				Name:        "Empty except block",
				Severity:    "medium",
				Description: "Empty except blocks can hide errors and make debugging difficult",
				CodePatterns: []string{
					`except(\s+\w+)?:\s*$`,
				},
			},
			FilePath:    filePath,
			LineNumber:  lineNumber,
			MatchedCode: matchedCode,
			Confidence:  0.85,
		})
	}

	// Check for bare except blocks
	bareExceptRe := regexp.MustCompile(`(?m)^(\s*)except:\s*`)
	bareExceptMatches := bareExceptRe.FindAllStringIndex(code, -1)
	for _, match := range bareExceptMatches {
		// Count line number
		lineNumber := 1 + strings.Count(code[:match[0]], "\n")
		matchedCode := code[match[0]:match[1]]

		matches = append(matches, core.Match{
			Signature: core.Signature{
				ID:          "PY012",
				Name:        "Bare except block",
				Severity:    "medium",
				Description: "Bare except blocks can catch unexpected exceptions and hide errors",
				CodePatterns: []string{
					`except:\s*`,
				},
			},
			FilePath:    filePath,
			LineNumber:  lineNumber,
			MatchedCode: matchedCode,
			Confidence:  0.9,
		})
	}

	return matches
} 