package mcp

import (
	"bufio"
	"context"
	"fmt"
	"github.com/Loccao102/Agent-Guard/internal/client"
	"github.com/Loccao102/Agent-Guard/internal/guard"
	"io"
	"os"
	"os/exec"
	"sync"
)

type RunnerOptions struct {
	Endpoint   string
	Agent      string
	ServerName string
	Command    string
	Args       []string
}
type safeWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *safeWriter) Line(p []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.w.Write(p); err != nil {
		return err
	}
	_, err := w.w.Write([]byte("\n"))
	return err
}

func Run(ctx context.Context, opts RunnerOptions) error {
	if opts.Command == "" {
		return fmt.Errorf("MCP server command is required")
	}
	if opts.Endpoint == "" {
		opts.Endpoint = "http://127.0.0.1:7788"
	}
	if opts.Agent == "" {
		opts.Agent = "mcp-client"
	}
	if opts.ServerName == "" {
		opts.ServerName = "server"
	}
	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	childIn, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	childErr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start MCP server: %w", err)
	}
	out := &safeWriter{w: os.Stdout}
	go io.Copy(os.Stderr, childErr)
	go func() {
		s := bufio.NewScanner(childOut)
		s.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for s.Scan() {
			_ = out.Line(append([]byte(nil), s.Bytes()...))
		}
	}()
	c := client.New(opts.Endpoint)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		msg, call, ok := ParseToolCall(line)
		if !ok {
			if _, err := childIn.Write(append(line, '\n')); err != nil {
				return err
			}
			continue
		}
		result, err := c.Evaluate(ctx, guard.Action{Agent: opts.Agent, Kind: "mcp", Value: ActionValue(opts.ServerName, call), Meta: map[string]string{"server": opts.ServerName, "tool": call.Name}}, true)
		if err != nil {
			response := DeniedResponse(msg.ID, "AgentGuard is unavailable", "critical")
			if len(response) > 0 {
				_ = out.Line(response)
			}
			continue
		}
		if result.Decision == "allow" {
			if _, err := childIn.Write(append(line, '\n')); err != nil {
				return err
			}
			continue
		}
		response := DeniedResponse(msg.ID, result.Reason, result.Risk)
		if len(response) > 0 {
			_ = out.Line(response)
		}
	}
	_ = childIn.Close()
	if err := scanner.Err(); err != nil {
		return err
	}
	return cmd.Wait()
}
