package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Scanner is a vulnerability scanner
type Scanner struct {
	detectors          []Detector
	parallel           bool
	incremental        bool
	confidenceThreshold float64
	cache              map[string][]Match
	cacheMutex         sync.RWMutex
}

// NewScanner creates a new scanner
func NewScanner() *Scanner {
	return &Scanner{
		detectors:          []Detector{},
		parallel:           false,
		incremental:        false,
		confidenceThreshold: 0.7,
		cache:              make(map[string][]Match),
	}
}

// RegisterDetector registers a detector
func (s *Scanner) RegisterDetector(detector Detector) {
	s.detectors = append(s.detectors, detector)
}

// SetParallel sets whether to use parallel processing
func (s *Scanner) SetParallel(parallel bool) {
	s.parallel = parallel
}

// IsParallel returns whether parallel processing is enabled
func (s *Scanner) IsParallel() bool {
	return s.parallel
}

// SetIncremental sets whether to use incremental scanning
func (s *Scanner) SetIncremental(incremental bool) {
	s.incremental = incremental
}

// IsIncremental returns whether incremental scanning is enabled
func (s *Scanner) IsIncremental() bool {
	return s.incremental
}

// SetConfidenceThreshold sets the confidence threshold
func (s *Scanner) SetConfidenceThreshold(threshold float64) {
	s.confidenceThreshold = threshold
}

// SupportedLanguages returns the list of supported languages
func (s *Scanner) SupportedLanguages() []string {
	languages := []string{}
	for _, detector := range s.detectors {
		languages = append(languages, detector.SupportedLanguages()...)
	}
	return languages
}

// ScanFile scans a file for vulnerabilities
func (s *Scanner) ScanFile(filePath string) ([]Match, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", filePath)
	}

	// Check if file is in cache
	if s.incremental {
		s.cacheMutex.RLock()
		if matches, ok := s.cache[filePath]; ok {
			s.cacheMutex.RUnlock()
			return matches, nil
		}
		s.cacheMutex.RUnlock()
	}

	// Scan file with each detector
	var allMatches []Match
	for _, detector := range s.detectors {
		matches, err := detector.DetectFile(filePath)
		if err != nil {
			return nil, err
		}

		// Filter matches by confidence threshold
		for _, match := range matches {
			if match.Confidence >= s.confidenceThreshold {
				allMatches = append(allMatches, match)
			}
		}
	}

	// Update cache
	if s.incremental {
		s.cacheMutex.Lock()
		s.cache[filePath] = allMatches
		s.cacheMutex.Unlock()
	}

	return allMatches, nil
}

// ScanDirectory scans a directory for vulnerabilities
func (s *Scanner) ScanDirectory(dirPath string, excludePatterns []string) (map[string][]Match, error) {
	// Check if directory exists
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("directory does not exist: %s", dirPath)
	}

	// Collect files to scan
	var filesToScan []string
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			// Check if directory should be excluded
			for _, pattern := range excludePatterns {
				if matched, _ := filepath.Match(pattern, info.Name()); matched {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Check if file should be excluded
		for _, pattern := range excludePatterns {
			if matched, _ := filepath.Match(pattern, info.Name()); matched {
				return nil
			}
		}

		// Check if file extension is supported
		ext := strings.ToLower(filepath.Ext(path))
		if ext == "" {
			return nil
		}

		// Remove the dot from the extension
		ext = ext[1:]

		// Check if any detector supports this file type
		for _, detector := range s.detectors {
			for _, lang := range detector.SupportedLanguages() {
				if lang == ext {
					filesToScan = append(filesToScan, path)
					return nil
				}
			}
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Scan files
	results := make(map[string][]Match)
	if s.parallel {
		// Parallel scanning
		var wg sync.WaitGroup
		resultsMutex := sync.Mutex{}

		for _, file := range filesToScan {
			wg.Add(1)
			go func(file string) {
				defer wg.Done()

				matches, err := s.ScanFile(file)
				if err != nil {
					// Log error but continue
					fmt.Fprintf(os.Stderr, "Error scanning file %s: %v\n", file, err)
					return
				}

				if len(matches) > 0 {
					resultsMutex.Lock()
					results[file] = matches
					resultsMutex.Unlock()
				}
			}(file)
		}

		wg.Wait()
	} else {
		// Sequential scanning
		for _, file := range filesToScan {
			matches, err := s.ScanFile(file)
			if err != nil {
				// Log error but continue
				fmt.Fprintf(os.Stderr, "Error scanning file %s: %v\n", file, err)
				continue
			}

			if len(matches) > 0 {
				results[file] = matches
			}
		}
	}

	return results, nil
} 