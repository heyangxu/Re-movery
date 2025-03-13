package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/re-movery/re-movery/internal/core"
	"github.com/re-movery/re-movery/internal/detectors"
)

// Server is the API server
type Server struct {
	scanner *core.Scanner
	router  *gin.Engine
}

// NewServer creates a new API server
func NewServer() *Server {
	server := &Server{
		scanner: core.NewScanner(),
		router:  gin.Default(),
	}

	// Register detectors
	server.scanner.RegisterDetector(detectors.NewPythonDetector())
	server.scanner.RegisterDetector(detectors.NewJavaScriptDetector())

	// Setup routes
	server.setupRoutes()

	return server
}

// setupRoutes sets up the routes for the API server
func (s *Server) setupRoutes() {
	// API routes
	api := s.router.Group("/api")
	{
		api.POST("/scan/code", s.scanCodeHandler)
		api.POST("/scan/file", s.scanFileHandler)
		api.POST("/scan/directory", s.scanDirectoryHandler)
		api.GET("/languages", s.languagesHandler)
	}

	// Health check
	s.router.GET("/health", s.healthHandler)
}

// Run runs the API server
func (s *Server) Run(host string, port int) error {
	return s.router.Run(fmt.Sprintf("%s:%d", host, port))
}

// scanCodeHandler handles code scanning
func (s *Server) scanCodeHandler(c *gin.Context) {
	// Parse request
	var request struct {
		Code     string `json:"code" binding:"required"`
		Language string `json:"language" binding:"required"`
		FileName string `json:"fileName"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request: " + err.Error(),
		})
		return
	}

	// Set default file name if not provided
	if request.FileName == "" {
		request.FileName = "code." + request.Language
	}

	// Check if language is supported
	supported := false
	for _, lang := range s.scanner.SupportedLanguages() {
		if lang == request.Language {
			supported = true
			break
		}
	}
	if !supported {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Unsupported language: " + request.Language,
		})
		return
	}

	// Create temporary file
	tempDir, err := ioutil.TempDir("", "re-movery-")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create temporary directory: " + err.Error(),
		})
		return
	}
	defer os.RemoveAll(tempDir)

	tempFile := filepath.Join(tempDir, request.FileName)
	if err := ioutil.WriteFile(tempFile, []byte(request.Code), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to write temporary file: " + err.Error(),
		})
		return
	}

	// Scan file
	results, err := s.scanner.ScanFile(tempFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to scan code: " + err.Error(),
		})
		return
	}

	// Generate summary
	summary := core.GenerateSummary(map[string][]core.Match{
		request.FileName: results,
	})

	// Return results
	c.JSON(http.StatusOK, gin.H{
		"results": map[string][]core.Match{
			request.FileName: results,
		},
		"summary": summary,
	})
}

// scanFileHandler handles file scanning
func (s *Server) scanFileHandler(c *gin.Context) {
	// Get file from form
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No file provided",
		})
		return
	}

	// Save file to temporary location
	tempFile := filepath.Join(os.TempDir(), file.Filename)
	if err := c.SaveUploadedFile(file, tempFile); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to save file",
		})
		return
	}
	defer os.Remove(tempFile)

	// Scan file
	results, err := s.scanner.ScanFile(tempFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to scan file: %v", err),
		})
		return
	}

	// Generate summary
	summary := core.GenerateSummary(map[string][]core.Match{
		file.Filename: results,
	})

	// Return results
	c.JSON(http.StatusOK, gin.H{
		"results": map[string][]core.Match{
			file.Filename: results,
		},
		"summary": summary,
	})
}

// scanDirectoryHandler handles directory scanning
func (s *Server) scanDirectoryHandler(c *gin.Context) {
	// Parse request
	var request struct {
		Directory       string   `json:"directory" binding:"required"`
		ExcludePatterns []string `json:"excludePatterns"`
		Parallel        bool     `json:"parallel"`
		Incremental     bool     `json:"incremental"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request: " + err.Error(),
		})
		return
	}

	// Check if directory exists
	if _, err := os.Stat(request.Directory); os.IsNotExist(err) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Directory does not exist",
		})
		return
	}

	// Set scanner options
	s.scanner.SetParallel(request.Parallel)
	s.scanner.SetIncremental(request.Incremental)

	// Scan directory
	results, err := s.scanner.ScanDirectory(request.Directory, request.ExcludePatterns)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Failed to scan directory: %v", err),
		})
		return
	}

	// Generate summary
	summary := core.GenerateSummary(results)

	// Return results
	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"summary": summary,
	})
}

// languagesHandler handles the supported languages request
func (s *Server) languagesHandler(c *gin.Context) {
	languages := s.scanner.SupportedLanguages()
	c.JSON(http.StatusOK, gin.H{
		"languages": languages,
	})
}

// healthHandler handles the health check request
func (s *Server) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
} 