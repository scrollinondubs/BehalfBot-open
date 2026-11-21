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

// IsolationCheck proves the worker cannot read the bridge's state (round 6
// M4): it runs a probe as the worker uid, the same way the worker is run,
// and fails unless every file in the state directory, and the directory
// listing itself, is denied. CI runs it inside the built image.
func IsolationCheck(ctx context.Context, cfg Config) error {
	if cfg.Worker.UID <= 0 {
		return errors.New("BRIDGE_WORKER_UID is not set: the worker would run as the bridge's own uid")
	}
	if err := HardenState(cfg); err != nil {
		return err
	}
	probe := filepath.Join(cfg.StateDir, ".isolation-probe")
	if err := os.WriteFile(probe, []byte("bridge-only\n"), 0o600); err != nil {
		return err
	}
	defer os.Remove(probe)
	entries, err := os.ReadDir(cfg.StateDir)
	if err != nil {
		return err
	}
	var paths []string
	for _, e := range entries {
		paths = append(paths, filepath.Join(cfg.StateDir, e.Name()))
	}
	script := `import json, os, sys
d, paths = sys.argv[1], sys.argv[2:]
out = {"uid": os.getuid(), "gid": os.getgid(), "files": {}}
try:
    os.listdir(d)
    out["listdir"] = "READABLE"
except OSError:
    out["listdir"] = "denied"
for p in paths:
    try:
        with open(p, "rb") as f:
            f.read(1)
        out["files"][p] = "READABLE"
    except OSError:
        out["files"][p] = "denied"
print(json.dumps(out))`
	spec := WorkerSpec{Argv: append([]string{"python3", "-I", "-c", script, cfg.StateDir}, paths...),
		UID: cfg.Worker.UID, GID: cfg.Worker.GID}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := spec.command(ctx)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("probe did not run as uid %d: %w", cfg.Worker.UID, err)
	}
	var res struct {
		UID, GID int
		Listdir  string
		Files    map[string]string
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return fmt.Errorf("probe output: %w", err)
	}
	fmt.Printf("worker uid=%d gid=%d listdir=%s files=%v\n", res.UID, res.GID, res.Listdir, res.Files)
	if res.UID != cfg.Worker.UID || res.GID != cfg.Worker.GID {
		return fmt.Errorf("probe ran as %d:%d, not %d:%d", res.UID, res.GID, cfg.Worker.UID, cfg.Worker.GID)
	}
	if res.Listdir != "denied" {
		return errors.New("the worker can list the bridge state directory")
	}
	for p, v := range res.Files {
		if v != "denied" {
			return fmt.Errorf("the worker can read %s", p)
		}
	}
	if len(res.Files) == 0 {
		return errors.New("no files were probed")
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
