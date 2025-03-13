package cmd

import (
	"fmt"
	"os"

	"github.com/re-movery/re-movery/internal/api"
	"github.com/spf13/cobra"
)

var (
	serverHost  string
	serverPort  int
	serverDebug bool
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the API server",
	Long: `Start the API server for Re-movery.
The API server provides a RESTful API for scanning files and directories for security vulnerabilities.

Examples:
  re-movery server
  re-movery server --host 0.0.0.0 --port 8081
  re-movery server --debug`,
	Run: func(cmd *cobra.Command, args []string) {
		// Create API server
		server := api.NewServer()
		
		// Start API server
		addr := fmt.Sprintf("%s:%d", serverHost, serverPort)
		fmt.Printf("Starting API server at http://%s\n", addr)
		
		if err := server.Run(serverHost, serverPort, serverDebug); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting API server: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	// Add flags
	serverCmd.Flags().StringVar(&serverHost, "host", "localhost", "Host to bind the API server to")
	serverCmd.Flags().IntVar(&serverPort, "port", 8081, "Port to bind the API server to")
	serverCmd.Flags().BoolVar(&serverDebug, "debug", false, "Enable debug mode")
} 