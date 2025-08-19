package log

import (
	"fmt"
	"log/slog"
	"os"
	"time"
)

// Logger provides structured logging capabilities
type Logger struct {
	logger  *slog.Logger
	verbose bool
	quiet   bool
}

// NewLogger creates a new logger instance
func NewLogger(verbose, quiet bool) *Logger {
	var level slog.Level

	switch {
	case quiet:
		level = slog.LevelError
	case verbose:
		level = slog.LevelDebug
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Customize timestamp format
			if a.Key == slog.TimeKey {
				return slog.Attr{
					Key:   a.Key,
					Value: slog.StringValue(time.Now().Format("15:04:05")),
				}
			}
			return a
		},
	}

	handler := slog.NewTextHandler(os.Stdout, opts)
	logger := slog.New(handler)

	return &Logger{
		logger:  logger,
		verbose: verbose,
		quiet:   quiet,
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, args ...interface{}) {
	if !l.verbose {
		return
	}
	l.logger.Debug(msg, args...)
}

// Info logs an info message
func (l *Logger) Info(msg string, args ...interface{}) {
	if l.quiet {
		return
	}
	l.logger.Info(msg, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, args ...interface{}) {
	l.logger.Warn(msg, args...)
}

// Error logs an error message
func (l *Logger) Error(msg string, args ...interface{}) {
	l.logger.Error(msg, args...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.logger.Error(msg, args...)
	os.Exit(1)
}

// Progress logs a progress message (always shown unless quiet)
func (l *Logger) Progress(msg string, args ...interface{}) {
	if l.quiet {
		return
	}

	// Format progress message with emoji
	formatted := fmt.Sprintf("🔄 %s", msg)
	l.logger.Info(formatted, args...)
}

// Success logs a success message (always shown unless quiet)
func (l *Logger) Success(msg string, args ...interface{}) {
	if l.quiet {
		return
	}

	// Format success message with emoji
	formatted := fmt.Sprintf("✅ %s", msg)
	l.logger.Info(formatted, args...)
}

// Critical logs a critical finding (always shown)
func (l *Logger) Critical(msg string, args ...interface{}) {
	// Format critical message with emoji
	formatted := fmt.Sprintf("🚨 %s", msg)
	l.logger.Error(formatted, args...)
}
