package mcp

import (
	"encoding/json"
	"net/http"
	"sort"
)

// JSON-RPC 2.0 error codes used by this server.
const (
	parseError     = -32700
	methodNotFound = -32601
	invalidParams  = -32602
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func writeResult(w http.ResponseWriter, id json.RawMessage, result any) {
	writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func writeError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	writeRPC(w, rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}})
}

func writeRPC(w http.ResponseWriter, resp rpcResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// toolText wraps a tool's result value as MCP tool-result content: a single text
// item holding the JSON-encoded value.
func toolText(v any) map[string]any {
	data, err := json.Marshal(v)
	if err != nil {
		return toolError("failed to encode result: " + err.Error())
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(data)}},
		"isError": false,
	}
}

// toolError wraps an error message as an MCP tool result with isError=true.
func toolError(msg string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}
}

func sortStrings(s []string) { sort.Strings(s) }
