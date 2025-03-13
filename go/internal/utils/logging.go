package utils

import (
    "io"
    "os"
    "sync"

    "github.com/sirupsen/logrus"
)

var (
    logger *logrus.Logger
    once   sync.Once
)

// GetLogger returns the singleton logger instance
func GetLogger() *logrus.Logger {
    once.Do(func() {
        logger = logrus.New()
        logger.SetFormatter(&logrus.TextFormatter{
            FullTimestamp: true,
        })
        logger.SetOutput(os.Stdout)
        logger.SetLevel(logrus.InfoLevel)
    })
    return logger
}

// FileLogger represents a logger that writes to a file
type FileLogger struct {
    *logrus.Logger
    file *os.File
}

// NewFileLogger creates a new file logger
func NewFileLogger(filename string) (*FileLogger, error) {
    file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        return nil, err
    }

    logger := logrus.New()
    logger.SetFormatter(&logrus.JSONFormatter{})
    logger.SetOutput(io.MultiWriter(file, os.Stdout))

    return &FileLogger{
        Logger: logger,
        file:   file,
    }, nil
}

// Close closes the log file
func (fl *FileLogger) Close() error {
    if fl.file != nil {
        return fl.file.Close()
    }
    return nil
}

// SetVerbosity sets the logging level based on verbosity
func SetVerbosity(verbose bool) {
    if verbose {
        GetLogger().SetLevel(logrus.DebugLevel)
    } else {
        GetLogger().SetLevel(logrus.InfoLevel)
    }
} 