package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

// Logger handles logging to both console and file
type Logger struct {
	fileLogger    *log.Logger
	consoleLogger *log.Logger
	file          *os.File
}

// NewLogger creates a new logger that writes to both console and file
func NewLogger(logFile string) (*Logger, error) {
	// Create logs directory if it doesn't exist
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file (create if doesn't exist, append if exists)
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Create multi-writer for console and file
	multiWriter := io.MultiWriter(os.Stdout, file)

	// Create loggers with timestamps
	fileLogger := log.New(file, "", log.LstdFlags)
	consoleLogger := log.New(multiWriter, "", log.LstdFlags)

	return &Logger{
		fileLogger:    fileLogger,
		consoleLogger: consoleLogger,
		file:          file,
	}, nil
}

// Close closes the log file
func (l *Logger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// Info logs an info message
func (l *Logger) Info(format string, v ...interface{}) {
	msg := fmt.Sprintf("[INFO] "+format, v...)
	l.consoleLogger.Println(msg)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, v ...interface{}) {
	msg := fmt.Sprintf("[WARN] "+format, v...)
	l.consoleLogger.Println(msg)
}

// Error logs an error message
func (l *Logger) Error(format string, v ...interface{}) {
	msg := fmt.Sprintf("[ERROR] "+format, v...)
	l.consoleLogger.Println(msg)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, v ...interface{}) {
	msg := fmt.Sprintf("[DEBUG] "+format, v...)
	l.consoleLogger.Println(msg)
}

// Packet logs packet information
func (l *Logger) Packet(format string, v ...interface{}) {
	msg := fmt.Sprintf("[PACKET] "+format, v...)
	l.consoleLogger.Println(msg)
}

// GetFileLogger returns the file-only logger (for compatibility)
func (l *Logger) GetFileLogger() *log.Logger {
	return l.fileLogger
}

// GetConsoleLogger returns the console logger
func (l *Logger) GetConsoleLogger() *log.Logger {
	return l.consoleLogger
}
