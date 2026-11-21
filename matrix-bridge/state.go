package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"maunium.net/go/mautrix/id"
)

// Everything here lives in the matrix-bridge-state volume, which no other
// service mounts.

const (
	credsFile    = "creds.json"
	pinFile      = "pin.json"
	lockFile     = "identity-lock.json"
	pickleFile   = "pickle.key"
	handledFile  = "handled-events.log"
	cryptoDBFile = "crypto.db"
	handledKeep  = 30 * 24 * time.Hour
)

type Creds struct {
	Homeserver  string      `json:"homeserver"`
	UserID      id.UserID   `json:"user_id"`
	DeviceID    id.DeviceID `json:"device_id"`
	AccessToken string      `json:"access_token"`
}

type Pin struct {
	Principal id.UserID  `json:"principal"`
	MasterKey id.Ed25519 `json:"master_key"`
	PinnedAt  int64      `json:"pinned_at"`
}

type IdentityLock struct {
	LockedAt int64  `json:"locked_at"`
	Reason   string `json:"reason"`
}

func writeJSON0600(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func LoadCreds(dir string) (*Creds, error) {
	var c Creds
	if err := readJSON(filepath.Join(dir, credsFile), &c); err != nil {
		return nil, err
	}
	if c.AccessToken == "" || c.DeviceID == "" || c.UserID == "" {
		return nil, errors.New("creds.json is incomplete")
	}
	return &c, nil
}

func SaveCreds(dir string, c *Creds) error { return writeJSON0600(filepath.Join(dir, credsFile), c) }

// LoadPin returns the pin for principal, or an empty pin when there is none
// or it was made for a different principal.
func LoadPin(dir string, principal id.UserID) (Pin, error) {
	var p Pin
	err := readJSON(filepath.Join(dir, pinFile), &p)
	if errors.Is(err, os.ErrNotExist) {
		return Pin{}, nil
	} else if err != nil {
		return Pin{}, err
	}
	if p.Principal != principal || len(p.MasterKey) != 43 {
		return Pin{}, nil
	}
	return p, nil
}

func SavePin(dir string, p Pin) error { return writeJSON0600(filepath.Join(dir, pinFile), p) }

func LoadLock(dir string) (*IdentityLock, error) {
	var l IdentityLock
	err := readJSON(filepath.Join(dir, lockFile), &l)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		// An unreadable lock file still means locked.
		return &IdentityLock{Reason: "lock file unreadable"}, nil
	}
	return &l, nil
}

func SaveLock(dir string, reason string) error {
	return writeJSON0600(filepath.Join(dir, lockFile), IdentityLock{LockedAt: time.Now().Unix(), Reason: reason})
}

func ClearLock(dir string) error {
	err := os.Remove(filepath.Join(dir, lockFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// PickleKey encrypts the Olm/Megolm pickles in crypto.db. It sits in the
// same volume, so it protects nothing against someone who can read the
// volume; it exists because the store requires one.
func PickleKey(dir string) ([]byte, error) {
	path := filepath.Join(dir, pickleFile)
	data, err := os.ReadFile(path)
	if err == nil && len(data) >= 32 {
		return data, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// HandledStore persists every event id the bridge has accepted, so a
// replayed event does nothing, also across restarts. An id is claimed
// before it is acted on: a crash between the two drops the message rather
// than repeating it.
type HandledStore struct {
	mu   sync.Mutex
	path string
	seen map[id.EventID]int64
}

func OpenHandledStore(dir string) (*HandledStore, error) {
	s := &HandledStore{path: filepath.Join(dir, handledFile), seen: map[id.EventID]int64{}}
	f, err := os.Open(s.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if f != nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			ts, evt, ok := strings.Cut(sc.Text(), " ")
			n, err := strconv.ParseInt(ts, 10, 64)
			if !ok || err != nil || evt == "" {
				continue
			}
			s.seen[id.EventID(evt)] = n
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return s, s.compact()
}

func (s *HandledStore) compact() error {
	cutoff := time.Now().Add(-handledKeep).Unix()
	var b strings.Builder
	for evt, ts := range s.seen {
		if ts < cutoff {
			delete(s.seen, evt)
			continue
		}
		fmt.Fprintf(&b, "%d %s\n", ts, evt)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Claim returns true the first time an event id is seen.
func (s *HandledStore) Claim(evt id.EventID) (bool, error) {
	if evt == "" || strings.ContainsAny(string(evt), " \n\r") {
		return false, errors.New("bad event id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[evt]; ok {
		return false, nil
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return false, err
	}
	now := time.Now().Unix()
	if _, err := fmt.Fprintf(f, "%d %s\n", now, evt); err != nil {
		f.Close()
		return false, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return false, err
	}
	if err := f.Close(); err != nil {
		return false, err
	}
	s.seen[evt] = now
	return true, nil
}

// HardenState makes the bridge state readable by the bridge's uid only and
// refuses to run a separate-uid worker unless the bridge can switch to it
// (round 6 M4). New files get 0600 from the umask.
func HardenState(cfg Config) error {
	syscall.Umask(0o077)
	if cfg.Worker.UID > 0 && os.Getuid() != 0 {
		return errors.New("BRIDGE_WORKER_UID is set but the bridge is not running as root with CAP_SETUID; refusing to run the worker as the bridge's own uid")
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(cfg.StateDir, 0o700); err != nil {
		return err
	}
	entries, err := os.ReadDir(cfg.StateDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		mode := os.FileMode(0o600)
		if e.IsDir() {
			mode = 0o700
		}
		if err := os.Chmod(filepath.Join(cfg.StateDir, e.Name()), mode); err != nil {
			return err
		}
	}
	return nil
}
