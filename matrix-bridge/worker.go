package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

// The Python worker holds the policy that already had tests: commands, the
// halt gate, draft approvals, opencode sessions and document extraction
// (PDF parsing happens only there). It runs as a child process per request,
// inside this container, fed JSON on stdin. It sees only messages that passed
// Accept, and attachments already decrypted here.
//
// Isolation (round 6 M4): in the container the bridge runs as root with only
// CAP_SETUID and CAP_SETGID, and starts the worker with a Credential, so the
// kernel switches the child to WorkerUID before exec. A non-root process has
// no capabilities, so the worker cannot switch back. The bridge state
// (token, pickle key, crypto store) is 0700 root and the worker cannot read
// it; `matrix-bridge isolation-check` proves that in CI.

type WorkerSpec struct {
	Argv []string
	UID  int // 0: same uid as the bridge (tests on a laptop)
	GID  int
}

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
	Attachments []WorkerAttachment `json:"attachments"`
	Notes       []string           `json:"notes"`
	Unsupported bool               `json:"unsupported"`
	Activate    []string           `json:"activate,omitempty"`
	AlertKind   string             `json:"alert_kind,omitempty"`
	// ReceivedAt is this bridge's clock when the message was accepted; model
	// replies quote it (round 6b N2).
	ReceivedAt float64 `json:"received_at,omitempty"`
}

type WorkerResponse struct {
	Handled bool     `json:"handled"`
	Replies []string `json:"replies"`
	// Activate lists one-time codes carried by Replies; they become usable
	// only after every reply was sent.
	Activate []string `json:"activate"`
}

func (w WorkerSpec) command(ctx context.Context, extra ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, w.Argv[0], append(append([]string{}, w.Argv[1:]...), extra...)...)
	if w.UID > 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid: uint32(w.UID), Gid: uint32(w.GID), Groups: []uint32{}}}
	}
	return cmd
}

func RunWorker(ctx context.Context, spec WorkerSpec, mode string, req WorkerRequest, timeout time.Duration) (*WorkerResponse, error) {
	in, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := spec.command(ctx, mode)
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
