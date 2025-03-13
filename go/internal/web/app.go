package web

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/re-movery/re-movery/internal/core"
	"github.com/re-movery/re-movery/internal/detectors"
)

// App is the web application
type App struct {
	scanner *core.Scanner
	router  *gin.Engine
}

// NewApp creates a new web application
func NewApp() *App {
	app := &App{
		scanner: core.NewScanner(),
		router:  gin.Default(),
	}

	// Register detectors
	app.scanner.RegisterDetector(detectors.NewPythonDetector())
	app.scanner.RegisterDetector(detectors.NewJavaScriptDetector())

	// Setup routes
	app.setupRoutes()

	return app
}

// setupRoutes sets up the routes for the web application
func (a *App) setupRoutes() {
	// Serve static files
	a.router.Static("/static", "./static")

	// Load templates
	a.router.LoadHTMLGlob("templates/*")

	// Routes
	a.router.GET("/", a.indexHandler)
	a.router.POST("/scan/file", a.scanFileHandler)
	a.router.POST("/scan/directory", a.scanDirectoryHandler)
	a.router.GET("/api/languages", a.languagesHandler)
	a.router.GET("/health", a.healthHandler)
}

// Run runs the web application
func (a *App) Run(host string, port int) error {
	return a.router.Run(fmt.Sprintf("%s:%d", host, port))
}

// indexHandler handles the index page
func (a *App) indexHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "index.html", gin.H{
		"title": "Re-movery - Security Scanner",
	})
}

// scanFileHandler handles file scanning
func (a *App) scanFileHandler(c *gin.Context) {
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
	results, err := a.scanner.ScanFile(tempFile)
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
func (a *App) scanDirectoryHandler(c *gin.Context) {
	// Get directory path from form
	directory := c.PostForm("directory")
	if directory == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "No directory provided",
		})
		return
	}

	// Check if directory exists
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Directory does not exist",
		})
		return
	}

	// Get exclude patterns
	excludePatterns := c.PostFormArray("exclude")

	// Scan directory
	results, err := a.scanner.ScanDirectory(directory, excludePatterns)
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
func (a *App) languagesHandler(c *gin.Context) {
	languages := a.scanner.SupportedLanguages()
	c.JSON(http.StatusOK, gin.H{
		"languages": languages,
	})
}

// healthHandler handles the health check request
func (a *App) healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
} 