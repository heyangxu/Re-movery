package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	outputDir string
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate files for integration with other tools",
	Long: `Generate files for integration with other tools.
Examples:
  re-movery generate github-action
  re-movery generate gitlab-ci
  re-movery generate vscode-extension`,
}

var generateGithubActionCmd = &cobra.Command{
	Use:   "github-action",
	Short: "Generate GitHub Actions workflow file",
	Long:  `Generate GitHub Actions workflow file for integrating Re-movery into your CI/CD pipeline.`,
	Run: func(cmd *cobra.Command, args []string) {
		outputPath := filepath.Join(outputDir, "re-movery-github-action.yml")
		if err := generateGithubActionFile(outputPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating GitHub Actions workflow file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("GitHub Actions workflow file generated: %s\n", outputPath)
	},
}

var generateGitlabCICmd = &cobra.Command{
	Use:   "gitlab-ci",
	Short: "Generate GitLab CI configuration file",
	Long:  `Generate GitLab CI configuration file for integrating Re-movery into your CI/CD pipeline.`,
	Run: func(cmd *cobra.Command, args []string) {
		outputPath := filepath.Join(outputDir, "re-movery-gitlab-ci.yml")
		if err := generateGitlabCIFile(outputPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating GitLab CI configuration file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("GitLab CI configuration file generated: %s\n", outputPath)
	},
}

var generateVSCodeExtensionCmd = &cobra.Command{
	Use:   "vscode-extension",
	Short: "Generate VS Code extension configuration files",
	Long:  `Generate VS Code extension configuration files for integrating Re-movery into VS Code.`,
	Run: func(cmd *cobra.Command, args []string) {
		outputPath := filepath.Join(outputDir, "re-movery-vscode")
		if err := generateVSCodeExtensionFiles(outputPath); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating VS Code extension configuration files: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("VS Code extension configuration files generated: %s\n", outputPath)
	},
}

func init() {
	// Add flags
	generateCmd.PersistentFlags().StringVar(&outputDir, "output-dir", ".", "Output directory for generated files")
	
	// Add subcommands
	generateCmd.AddCommand(generateGithubActionCmd)
	generateCmd.AddCommand(generateGitlabCICmd)
	generateCmd.AddCommand(generateVSCodeExtensionCmd)
}

// generateGithubActionFile generates a GitHub Actions workflow file
func generateGithubActionFile(outputPath string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}
	
	// GitHub Actions workflow file content
	content := `name: Re-movery Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Go
        uses: actions/setup-go@v2
        with:
          go-version: 1.17
      
      - name: Install Re-movery
        run: |
          go install github.com/re-movery/re-movery@latest
      
      - name: Run Re-movery Security Scan
        run: |
          re-movery scan --dir . --exclude "vendor,node_modules,*.min.js" --output report.html --format html
      
      - name: Upload Scan Results
        uses: actions/upload-artifact@v2
        with:
          name: security-scan-report
          path: report.html
`
	
	// Write content to file
	return os.WriteFile(outputPath, []byte(content), 0644)
}

// generateGitlabCIFile generates a GitLab CI configuration file
func generateGitlabCIFile(outputPath string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return err
	}
	
	// GitLab CI configuration file content
	content := `stages:
  - security-scan

security-scan:
  stage: security-scan
  image: golang:1.17
  script:
    - go install github.com/re-movery/re-movery@latest
    - re-movery scan --dir . --exclude "vendor,node_modules,*.min.js" --output report.html --format html
  artifacts:
    paths:
      - report.html
    expire_in: 1 week
`
	
	// Write content to file
	return os.WriteFile(outputPath, []byte(content), 0644)
}

// generateVSCodeExtensionFiles generates VS Code extension configuration files
func generateVSCodeExtensionFiles(outputPath string) error {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		return err
	}
	
	// package.json content
	packageJSON := `{
  "name": "re-movery-vscode",
  "displayName": "Re-movery Security Scanner",
  "description": "Security vulnerability scanner for VS Code",
  "version": "0.1.0",
  "engines": {
    "vscode": "^1.60.0"
  },
  "categories": [
    "Linters",
    "Security"
  ],
  "activationEvents": [
    "onLanguage:python",
    "onLanguage:javascript",
    "onCommand:re-movery.scanFile",
    "onCommand:re-movery.scanWorkspace"
  ],
  "main": "./extension.js",
  "contributes": {
    "commands": [
      {
        "command": "re-movery.scanFile",
        "title": "Re-movery: Scan Current File"
      },
      {
        "command": "re-movery.scanWorkspace",
        "title": "Re-movery: Scan Workspace"
      }
    ],
    "configuration": {
      "title": "Re-movery",
      "properties": {
        "re-movery.serverHost": {
          "type": "string",
          "default": "localhost",
          "description": "Host of the Re-movery API server"
        },
        "re-movery.serverPort": {
          "type": "number",
          "default": 8081,
          "description": "Port of the Re-movery API server"
        },
        "re-movery.enableBackgroundScanning": {
          "type": "boolean",
          "default": true,
          "description": "Enable background scanning of files"
        }
      }
    }
  }
}
`
	
	// extension.js content
	extensionJS := `const vscode = require('vscode');
const path = require('path');
const fs = require('fs');
const http = require('http');

let diagnosticCollection;

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
    console.log('Re-movery extension is now active');
    
    // Create diagnostic collection
    diagnosticCollection = vscode.languages.createDiagnosticCollection('re-movery');
    context.subscriptions.push(diagnosticCollection);
    
    // Register commands
    context.subscriptions.push(
        vscode.commands.registerCommand('re-movery.scanFile', scanCurrentFile),
        vscode.commands.registerCommand('re-movery.scanWorkspace', scanWorkspace)
    );
    
    // Register event handlers
    if (vscode.workspace.getConfiguration('re-movery').get('enableBackgroundScanning')) {
        context.subscriptions.push(
            vscode.workspace.onDidSaveTextDocument(scanDocument),
            vscode.window.onDidChangeActiveTextEditor(editor => {
                if (editor) {
                    scanDocument(editor.document);
                }
            })
        );
    }
}

function deactivate() {
    diagnosticCollection.clear();
}

async function scanCurrentFile() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showInformationMessage('No file is currently open');
        return;
    }
    
    await scanDocument(editor.document);
    vscode.window.showInformationMessage('File scan completed');
}

async function scanWorkspace() {
    if (!vscode.workspace.workspaceFolders) {
        vscode.window.showInformationMessage('No workspace is open');
        return;
    }
    
    const workspaceFolder = vscode.workspace.workspaceFolders[0].uri.fsPath;
    
    vscode.window.withProgress({
        location: vscode.ProgressLocation.Notification,
        title: 'Scanning workspace for security vulnerabilities',
        cancellable: false
    }, async (progress) => {
        progress.report({ increment: 0 });
        
        try {
            const results = await scanDirectory(workspaceFolder);
            updateDiagnostics(results);
            
            const totalIssues = Object.values(results).reduce((sum, matches) => sum + matches.length, 0);
            vscode.window.showInformationMessage(\`Workspace scan completed. Found \${totalIssues} issues.\`);
            
            progress.report({ increment: 100 });
        } catch (error) {
            vscode.window.showErrorMessage(\`Error scanning workspace: \${error.message}\`);
        }
    });
}

async function scanDocument(document) {
    // Check if file type is supported
    if (!isSupportedFileType(document)) {
        return;
    }
    
    try {
        const results = await scanCode(document.getText(), document.fileName);
        updateDiagnosticsForFile(document.uri, results);
    } catch (error) {
        console.error('Error scanning document:', error);
    }
}

function isSupportedFileType(document) {
    const supportedLanguages = ['python', 'javascript'];
    return supportedLanguages.includes(document.languageId);
}

async function scanCode(code, filename) {
    const config = vscode.workspace.getConfiguration('re-movery');
    const host = config.get('serverHost');
    const port = config.get('serverPort');
    
    return new Promise((resolve, reject) => {
        const postData = JSON.stringify({
            code: code,
            filename: path.basename(filename)
        });
        
        const options = {
            hostname: host,
            port: port,
            path: '/api/scan/code',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };
        
        const req = http.request(options, (res) => {
            let data = '';
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                if (res.statusCode === 200) {
                    try {
                        const response = JSON.parse(data);
                        resolve(response.results || {});
                    } catch (error) {
                        reject(new Error('Invalid response from server'));
                    }
                } else {
                    reject(new Error(\`Server returned status code \${res.statusCode}\`));
                }
            });
        });
        
        req.on('error', (error) => {
            reject(new Error(\`Error connecting to Re-movery server: \${error.message}\`));
        });
        
        req.write(postData);
        req.end();
    });
}

async function scanDirectory(directory) {
    const config = vscode.workspace.getConfiguration('re-movery');
    const host = config.get('serverHost');
    const port = config.get('serverPort');
    
    return new Promise((resolve, reject) => {
        const postData = JSON.stringify({
            directory: directory
        });
        
        const options = {
            hostname: host,
            port: port,
            path: '/api/scan/directory',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };
        
        const req = http.request(options, (res) => {
            let data = '';
            
            res.on('data', (chunk) => {
                data += chunk;
            });
            
            res.on('end', () => {
                if (res.statusCode === 200) {
                    try {
                        const response = JSON.parse(data);
                        resolve(response.results || {});
                    } catch (error) {
                        reject(new Error('Invalid response from server'));
                    }
                } else {
                    reject(new Error(\`Server returned status code \${res.statusCode}\`));
                }
            });
        });
        
        req.on('error', (error) => {
            reject(new Error(\`Error connecting to Re-movery server: \${error.message}\`));
        });
        
        req.write(postData);
        req.end();
    });
}

function updateDiagnostics(results) {
    // Clear all diagnostics
    diagnosticCollection.clear();
    
    // Update diagnostics for each file
    for (const [filePath, matches] of Object.entries(results)) {
        const uri = vscode.Uri.file(filePath);
        updateDiagnosticsForFile(uri, { [filePath]: matches });
    }
}

function updateDiagnosticsForFile(uri, results) {
    const filePath = uri.fsPath;
    const matches = results[filePath] || [];
    
    if (matches.length === 0) {
        diagnosticCollection.delete(uri);
        return;
    }
    
    const diagnostics = matches.map(match => {
        const range = new vscode.Range(
            match.line - 1, 0,
            match.line - 1, 1000
        );
        
        const severity = getSeverity(match.severity);
        
        return new vscode.Diagnostic(
            range,
            \`\${match.name}: \${match.description}\`,
            severity
        );
    });
    
    diagnosticCollection.set(uri, diagnostics);
}

function getSeverity(severity) {
    switch (severity.toLowerCase()) {
        case 'high':
            return vscode.DiagnosticSeverity.Error;
        case 'medium':
            return vscode.DiagnosticSeverity.Warning;
        case 'low':
            return vscode.DiagnosticSeverity.Information;
        default:
            return vscode.DiagnosticSeverity.Hint;
    }
}

module.exports = {
    activate,
    deactivate
};
`
	
	// README.md content
	readmeMD := `# Re-movery Security Scanner for VS Code

This extension integrates the Re-movery security scanner into VS Code, providing real-time security vulnerability detection for your code.

## Features

- Scan individual files for security vulnerabilities
- Scan entire workspaces for security vulnerabilities
- Real-time scanning as you type
- Detailed diagnostics with severity levels
- Integration with the Re-movery API server

## Requirements

- VS Code 1.60.0 or higher
- Re-movery API server running locally or remotely

## Extension Settings

This extension contributes the following settings:

* \`re-movery.serverHost\`: Host of the Re-movery API server
* \`re-movery.serverPort\`: Port of the Re-movery API server
* \`re-movery.enableBackgroundScanning\`: Enable background scanning of files

## Known Issues

- Currently only supports Python and JavaScript files
- Requires a running Re-movery API server

## Release Notes

### 0.1.0

Initial release of the Re-movery Security Scanner for VS Code
`
	
	// Write files
	if err := os.WriteFile(filepath.Join(outputPath, "package.json"), []byte(packageJSON), 0644); err != nil {
		return err
	}
	
	if err := os.WriteFile(filepath.Join(outputPath, "extension.js"), []byte(extensionJS), 0644); err != nil {
		return err
	}
	
	if err := os.WriteFile(filepath.Join(outputPath, "README.md"), []byte(readmeMD), 0644); err != nil {
		return err
	}
	
	return nil
} 