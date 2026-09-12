package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
)

type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type ToolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func ParseToolCall(line []byte) (Message, ToolCall, bool) {
	var msg Message
	if err := json.Unmarshal(line, &msg); err != nil || msg.Method != "tools/call" {
		return Message{}, ToolCall{}, false
	}
	var p ToolCall
	if err := json.Unmarshal(msg.Params, &p); err != nil || strings.TrimSpace(p.Name) == "" {
		return Message{}, ToolCall{}, false
	}
	return msg, p, true
}
func ActionValue(server string, call ToolCall) string {
	value := server + "/" + call.Name
	if len(call.Arguments) > 0 && string(call.Arguments) != "null" {
		var b bytes.Buffer
		if json.Compact(&b, call.Arguments) == nil {
			value += " " + b.String()
		}
	}
	return value
}
func DeniedResponse(id json.RawMessage, reason, risk string) []byte {
	if len(id) == 0 {
		return nil
	}
	payload := map[string]any{"jsonrpc": "2.0", "id": json.RawMessage(id), "error": map[string]any{"code": -32001, "message": "AgentGuard policy did not permit this MCP tool call", "data": map[string]string{"reason": reason, "risk": risk}}}
	b, _ := json.Marshal(payload)
	return b
}
