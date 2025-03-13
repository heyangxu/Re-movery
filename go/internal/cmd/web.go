package cmd

import (
	"fmt"
	"os"

	"github.com/re-movery/re-movery/internal/web"
	"github.com/spf13/cobra"
)

var (
	webHost  string
	webPort  int
	webDebug bool
)

var webCmd = &cobra.Command{
	Use:   "web",
	Short: "Start the web interface",
	Long: `Start the web interface for Re-movery.
The web interface provides a user-friendly way to scan files and directories for security vulnerabilities.

Examples:
  re-movery web
  re-movery web --host 0.0.0.0 --port 8080
  re-movery web --debug`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create web app
		app := web.NewApp()
		
		// Start web server
		addr := fmt.Sprintf("%s:%d", webHost, webPort)
		fmt.Printf("Starting web server at http://%s\n", addr)
		
		if err := app.Run(webHost, webPort, webDebug); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting web server: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	// Add flags
	webCmd.Flags().StringVar(&webHost, "host", "localhost", "Host to bind the web server to")
	webCmd.Flags().IntVar(&webPort, "port", 8080, "Port to bind the web server to")
	webCmd.Flags().BoolVar(&webDebug, "debug", false, "Enable debug mode")
} 