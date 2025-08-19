package runner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ezrec/ezrec/internal/log"
)

// CommandResult represents the result of a command execution
type CommandResult struct {
	Command    string        `json:"command"`
	Args       []string      `json:"args"`
	ExitCode   int           `json:"exit_code"`
	Duration   time.Duration `json:"duration"`
	Output     []string      `json:"output"`
	Error      string        `json:"error,omitempty"`
	Successful bool          `json:"successful"`
}

// Executor handles command execution with streaming output
type Executor struct {
	logger *log.Logger
	mutex  sync.RWMutex
}

// NewExecutor creates a new command executor
func NewExecutor(logger *log.Logger) *Executor {
	return &Executor{
		logger: logger,
	}
}

// Execute runs a command and returns the result
func (e *Executor) Execute(ctx context.Context, command string, args ...string) (*CommandResult, error) {
	start := time.Now()

	e.logger.Debug("Executing command", "command", command, "args", args)

	cmd := exec.CommandContext(ctx, command, args...)

	// Create pipes for stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return &CommandResult{
			Command:    command,
			Args:       args,
			ExitCode:   -1,
			Duration:   time.Since(start),
			Error:      err.Error(),
			Successful: false,
		}, err
	}

	// Read output concurrently
	var output []string
	var errorOutput []string
	var wg sync.WaitGroup

	wg.Add(2)

	// Read stdout
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				e.mutex.Lock()
				output = append(output, line)
				e.mutex.Unlock()
				e.logger.Debug("Command output", "line", line)
			}
		}
	}()

	// Read stderr
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				e.mutex.Lock()
				errorOutput = append(errorOutput, line)
				e.mutex.Unlock()
				e.logger.Debug("Command error", "line", line)
			}
		}
	}()

	// Wait for command to finish
	err = cmd.Wait()
	wg.Wait()

	duration := time.Since(start)
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	result := &CommandResult{
		Command:    command,
		Args:       args,
		ExitCode:   exitCode,
		Duration:   duration,
		Output:     output,
		Successful: exitCode == 0,
	}

	if len(errorOutput) > 0 {
		result.Error = strings.Join(errorOutput, "\n")
	}

	if err != nil && exitCode != 0 {
		e.logger.Warn("Command failed", "command", command, "exit_code", exitCode, "error", err)
	} else {
		e.logger.Debug("Command completed", "command", command, "duration", duration, "lines", len(output))
	}

	return result, nil
}

// ExecuteWithInput runs a command with input and returns the result
func (e *Executor) ExecuteWithInput(ctx context.Context, input string, command string, args ...string) (*CommandResult, error) {
	start := time.Now()

	e.logger.Debug("Executing command with input", "command", command, "args", args, "input_lines", strings.Count(input, "\n")+1)

	cmd := exec.CommandContext(ctx, command, args...)

	// Set up pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return &CommandResult{
			Command:    command,
			Args:       args,
			ExitCode:   -1,
			Duration:   time.Since(start),
			Error:      err.Error(),
			Successful: false,
		}, err
	}

	// Write input and close stdin
	go func() {
		defer stdin.Close()
		if _, err := io.WriteString(stdin, input); err != nil {
			e.logger.Error("Failed to write input to command", "error", err)
		}
	}()

	// Read output concurrently
	var output []string
	var errorOutput []string
	var wg sync.WaitGroup

	wg.Add(2)

	// Read stdout
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				e.mutex.Lock()
				output = append(output, line)
				e.mutex.Unlock()
				e.logger.Debug("Command output", "line", line)
			}
		}
	}()

	// Read stderr
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				e.mutex.Lock()
				errorOutput = append(errorOutput, line)
				e.mutex.Unlock()
				e.logger.Debug("Command error", "line", line)
			}
		}
	}()

	// Wait for command to finish
	err = cmd.Wait()
	wg.Wait()

	duration := time.Since(start)
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	result := &CommandResult{
		Command:    command,
		Args:       args,
		ExitCode:   exitCode,
		Duration:   duration,
		Output:     output,
		Successful: exitCode == 0,
	}

	if len(errorOutput) > 0 {
		result.Error = strings.Join(errorOutput, "\n")
	}

	if err != nil && exitCode != 0 {
		e.logger.Warn("Command with input failed", "command", command, "exit_code", exitCode, "error", err)
	} else {
		e.logger.Debug("Command with input completed", "command", command, "duration", duration, "lines", len(output))
	}

	return result, nil
}

// CheckTool verifies if a tool is available in PATH
func (e *Executor) CheckTool(toolName string) bool {
	_, err := exec.LookPath(toolName)
	available := err == nil

	if available {
		e.logger.Debug("Tool found", "tool", toolName)
	} else {
		e.logger.Warn("Tool not found in PATH", "tool", toolName)
	}

	return available
}

// GetToolVersion gets the version of a tool
func (e *Executor) GetToolVersion(ctx context.Context, toolName string, versionArgs ...string) (string, error) {
	if len(versionArgs) == 0 {
		versionArgs = []string{"--version"}
	}

	result, err := e.Execute(ctx, toolName, versionArgs...)
	if err != nil {
		return "", err
	}

	if !result.Successful {
		return "", fmt.Errorf("tool version check failed: %s", result.Error)
	}

	if len(result.Output) > 0 {
		return result.Output[0], nil
	}

	return "unknown", nil
}

// StreamingExecutor provides real-time output streaming
type StreamingExecutor struct {
	logger *log.Logger
}

// NewStreamingExecutor creates a new streaming executor
func NewStreamingExecutor(logger *log.Logger) *StreamingExecutor {
	return &StreamingExecutor{
		logger: logger,
	}
}

// ExecuteWithCallback runs a command and calls the callback for each output line
func (se *StreamingExecutor) ExecuteWithCallback(ctx context.Context, callback func(string), command string, args ...string) (*CommandResult, error) {
	start := time.Now()

	se.logger.Debug("Executing command with streaming", "command", command, "args", args)

	cmd := exec.CommandContext(ctx, command, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return &CommandResult{
			Command:    command,
			Args:       args,
			ExitCode:   -1,
			Duration:   time.Since(start),
			Error:      err.Error(),
			Successful: false,
		}, err
	}

	var output []string
	var errorOutput []string
	var wg sync.WaitGroup
	var mutex sync.Mutex

	wg.Add(2)

	// Stream stdout
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				mutex.Lock()
				output = append(output, line)
				mutex.Unlock()

				if callback != nil {
					callback(line)
				}
			}
		}
	}()

	// Stream stderr
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				mutex.Lock()
				errorOutput = append(errorOutput, line)
				mutex.Unlock()
			}
		}
	}()

	err = cmd.Wait()
	wg.Wait()

	duration := time.Since(start)
	exitCode := 0
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = -1
		}
	}

	result := &CommandResult{
		Command:    command,
		Args:       args,
		ExitCode:   exitCode,
		Duration:   duration,
		Output:     output,
		Successful: exitCode == 0,
	}

	if len(errorOutput) > 0 {
		result.Error = strings.Join(errorOutput, "\n")
	}

	return result, nil
}
