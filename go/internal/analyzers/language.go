package analyzers

import (
    "go/ast"
    "go/parser"
    "go/token"
    "path/filepath"
)

// LanguageAnalyzer defines the interface for language analyzers
type LanguageAnalyzer interface {
    ParseFile(filename string) (ast.Node, error)
    ExtractFunctions(node ast.Node) []ast.Node
    ExtractClasses(node ast.Node) []ast.Node
    ExtractImports(node ast.Node) []string
    ExtractVariables(node ast.Node) []ast.Node
}

// GoAnalyzer implements LanguageAnalyzer for Go language
type GoAnalyzer struct {
    fset *token.FileSet
}

// NewGoAnalyzer creates a new Go language analyzer
func NewGoAnalyzer() *GoAnalyzer {
    return &GoAnalyzer{
        fset: token.NewFileSet(),
    }
}

// ParseFile parses a Go source file
func (ga *GoAnalyzer) ParseFile(filename string) (ast.Node, error) {
    return parser.ParseFile(ga.fset, filename, nil, parser.AllErrors)
}

// ExtractFunctions extracts function declarations from an AST
func (ga *GoAnalyzer) ExtractFunctions(node ast.Node) []ast.Node {
    var functions []ast.Node
    ast.Inspect(node, func(n ast.Node) bool {
        if fn, ok := n.(*ast.FuncDecl); ok {
            functions = append(functions, fn)
        }
        return true
    })
    return functions
}

// ExtractClasses extracts type declarations from an AST
func (ga *GoAnalyzer) ExtractClasses(node ast.Node) []ast.Node {
    var types []ast.Node
    ast.Inspect(node, func(n ast.Node) bool {
        if t, ok := n.(*ast.TypeSpec); ok {
            types = append(types, t)
        }
        return true
    })
    return types
}

// ExtractImports extracts import declarations from an AST
func (ga *GoAnalyzer) ExtractImports(node ast.Node) []string {
    var imports []string
    ast.Inspect(node, func(n ast.Node) bool {
        if imp, ok := n.(*ast.ImportSpec); ok {
            imports = append(imports, imp.Path.Value)
        }
        return true
    })
    return imports
}

// ExtractVariables extracts variable declarations from an AST
func (ga *GoAnalyzer) ExtractVariables(node ast.Node) []ast.Node {
    var variables []ast.Node
    ast.Inspect(node, func(n ast.Node) bool {
        if v, ok := n.(*ast.ValueSpec); ok {
            variables = append(variables, v)
        }
        return true
    })
    return variables
}

// GetFileLanguage determines the programming language of a file
func GetFileLanguage(filename string) string {
    ext := filepath.Ext(filename)
    switch ext {
    case ".go":
        return "go"
    case ".java":
        return "java"
    case ".py":
        return "python"
    case ".js":
        return "javascript"
    case ".ts":
        return "typescript"
    default:
        return "unknown"
    }
} 