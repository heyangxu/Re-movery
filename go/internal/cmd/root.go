package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "re-movery",
	Short: "Re-movery - Security Vulnerability Scanner",
	Long: `Re-movery is a powerful security vulnerability scanner designed to detect 
potential security issues in your codebase. It supports multiple programming 
languages and provides various interfaces for scanning and reporting.`,
	Run: func(cmd *cobra.Command, args []string) {
		// If no subcommand is provided, print help
		cmd.Help()
	},
}

// Execute executes the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Add global flags
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringP("config", "c", "", "Config file path")

	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(webCmd)
	rootCmd.AddCommand(serverCmd)
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(versionCmd)
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Re-movery v1.0.0")
	},
} 