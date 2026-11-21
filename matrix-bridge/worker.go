package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// The Python worker holds the policy that already had tests: commands, the
// halt gate, draft approvals, opencode sessions and document extraction. It
// runs as a child process per request, inside this container, fed JSON on
// stdin. It never sees Matrix, keys or tokens: only messages that passed
// Accept, and attachments already decrypted here.

type WorkerAttachment struct {
	Name string `json:"name"`
	Mime string `json:"mime"`
	Size int    `json:"size"`
	Data []byte `json:"data_b64"`
}

type WorkerRequest struct {
	EventID     string             `json:"event_id"`
	EventTS     float64            `json:"event_ts"`
	Room        string             `json:"room"`
	Text        string             `json:"text"`
	IsReply     bool               `json:"is_reply"`
	Attachments []WorkerAttachment `json:"attachments"`
	Notes       []string           `json:"notes"`
	Unsupported bool               `json:"unsupported"`
}

type WorkerResponse struct {
	Handled bool     `json:"handled"`
	Replies []string `json:"replies"`
}

func RunWorker(ctx context.Context, argv []string, mode string, req WorkerRequest, timeout time.Duration) (*WorkerResponse, error) {
	in, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], append(append([]string{}, argv[1:]...), mode)...)
	cmd.Stdin = bytes.NewReader(in)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("worker %s: %w", mode, err)
	}
	var resp WorkerResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("worker %s returned invalid JSON", mode)
	}
	return &resp, nil
}
