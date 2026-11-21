package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const probeScript = `import json, os, sys
spec = json.loads(sys.argv[1])
out = {"uid": os.getuid(), "gid": os.getgid(), "results": {}}
for d in spec.get("list", []):
    try:
        os.listdir(d)
        out["results"]["list " + d] = "ALLOWED"
    except OSError:
        out["results"]["list " + d] = "denied"
for p in spec.get("read", []):
    try:
        with open(p, "rb") as f:
            f.read(1)
        out["results"]["read " + p] = "ALLOWED"
    except OSError:
        out["results"]["read " + p] = "denied"
for d in spec.get("write", []):
    t = os.path.join(d, ".isolation-write-probe")
    try:
        with open(t, "w") as f:
            f.write("x")
        os.remove(t)
        out["results"]["write " + d] = "ALLOWED"
    except OSError:
        out["results"]["write " + d] = "denied"
print(json.dumps(out))`

type probeSpec struct {
	List  []string `json:"list,omitempty"`
	Read  []string `json:"read,omitempty"`
	Write []string `json:"write,omitempty"`
}

// probe runs the probe as w's uid and returns its results after checking it
// really ran as that uid.
func probe(ctx context.Context, w WorkerSpec, spec probeSpec) (map[string]string, error) {
	arg, _ := json.Marshal(spec)
	p := WorkerSpec{Argv: []string{"python3", "-I", "-c", probeScript, string(arg)}, UID: w.UID, GID: w.GID}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := p.command(ctx)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("probe did not run as uid %d: %w", w.UID, err)
	}
	var res struct {
		UID, GID int
		Results  map[string]string
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return nil, fmt.Errorf("probe output: %w", err)
	}
	if res.UID != w.UID || res.GID != w.GID {
		return nil, fmt.Errorf("probe ran as %d:%d, not %d:%d", res.UID, res.GID, w.UID, w.GID)
	}
	fmt.Printf("uid %d: %v\n", res.UID, res.Results)
	return res.Results, nil
}

// IsolationCheck proves, from inside the container as compose runs it:
//   - the worker uid cannot list or read the bridge state (round 6 M4);
//   - the chat uid, which parses PDFs and relays model output, cannot list
//     or read the bridge state or the worker's codes, and cannot write
//     approvals, the halt and meter flags or the alert spool (round 6b N6).
//
// CI runs it in the built image.
func IsolationCheck(ctx context.Context, cfg Config) error {
	if cfg.Worker.UID <= 0 || cfg.ChatWorker.UID <= 0 {
		return errors.New("BRIDGE_WORKER_UID and BRIDGE_CHAT_UID must both be set")
	}
	if cfg.Worker.UID == cfg.ChatWorker.UID {
		return errors.New("the chat step must run as a different uid from the worker")
	}
	if err := HardenState(cfg); err != nil {
		return err
	}
	marker := filepath.Join(cfg.StateDir, ".isolation-probe")
	if err := os.WriteFile(marker, []byte("bridge-only\n"), 0o600); err != nil {
		return err
	}
	defer os.Remove(marker)
	entries, err := os.ReadDir(cfg.StateDir)
	if err != nil {
		return err
	}
	var state []string
	for _, e := range entries {
		state = append(state, filepath.Join(cfg.StateDir, e.Name()))
	}
	workerState := envOr("WORKER_STATE_DIR", "/state/matrix-worker")
	checks := []struct {
		who  string
		w    WorkerSpec
		spec probeSpec
	}{
		{"worker", cfg.Worker, probeSpec{List: []string{cfg.StateDir}, Read: state}},
		{"chat", cfg.ChatWorker, probeSpec{
			List: []string{cfg.StateDir, workerState},
			Read: append(state, filepath.Join(workerState, "codes.json")),
			Write: []string{envOr("APPROVALS_DIR", "/state/approvals"), envOr("CONTROL_DIR", "/state/control"),
				envOr("ALERT_SPOOL_DIR", "/state/alerts"), workerState, cfg.StateDir},
		}},
	}
	// Positive control: the worker uid can write where it must, so the chat
	// uid's denials come from the uid split, not from a read-only mount.
	ok, err := probe(ctx, cfg.Worker, probeSpec{Write: []string{envOr("APPROVALS_DIR", "/state/approvals"),
		envOr("CONTROL_DIR", "/state/control"), envOr("ALERT_SPOOL_DIR", "/state/alerts"), workerState}})
	if err != nil {
		return err
	}
	for what, v := range ok {
		if v != "ALLOWED" {
			return fmt.Errorf("positive control failed: the worker uid cannot %s (mount it writable)", what)
		}
	}
	for _, c := range checks {
		res, err := probe(ctx, c.w, c.spec)
		if err != nil {
			return err
		}
		if len(res) == 0 {
			return fmt.Errorf("%s: nothing was probed", c.who)
		}
		for what, v := range res {
			if v != "denied" {
				return fmt.Errorf("%s uid %d can %s", c.who, c.w.UID, what)
			}
		}
	}
	return nil
}

// Status prints the bridge's identity state for the host (round 6 L1): the
// identity-lock alert travels through a room the homeserver admin runs and
// can be dropped; this cannot.
func Status(cfg Config) error {
	pin, err := LoadPin(cfg.StateDir, cfg.Principal)
	if err != nil {
		return err
	}
	if creds, err := LoadCreds(cfg.StateDir); err == nil {
		fmt.Printf("login: %s device %s\n", creds.UserID, creds.DeviceID)
	} else {
		fmt.Println("login: NONE (run setup)")
	}
	if pin.MasterKey == "" {
		fmt.Println("pin: NONE (run setup)")
	} else {
		fmt.Printf("pin: %s %s (since %s)\n", pin.Principal, Fingerprint(pin.MasterKey), time.Unix(pin.PinnedAt, 0).UTC().Format(time.RFC3339))
	}
	l, err := LoadLock(cfg.StateDir)
	if err != nil {
		return err
	}
	if l != nil {
		fmt.Printf("IDENTITY LOCK: %s (since %s). Chat and commands are refused until setup re-pins.\n",
			l.Reason, time.Unix(l.LockedAt, 0).UTC().Format(time.RFC3339))
		return errors.New("identity-locked")
	}
	fmt.Println("identity lock: none")
	return nil
}
