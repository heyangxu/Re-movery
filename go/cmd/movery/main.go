package main

import (
	"fmt"
	"os"

	"github.com/re-movery/re-movery/internal/cmd"
)

func main() {
	// 执行根命令
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
} 