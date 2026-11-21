package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Alerter writes content-free alerts to the spool jill-control drains (it
// posts them to the unencrypted alerts room, so fixed texts only). One
// alert per kind per hour.
type Alerter struct {
	dir  string
	mu   sync.Mutex
	last map[string]time.Time
}

func NewAlerter(dir string) *Alerter { return &Alerter{dir: dir, last: map[string]time.Time{}} }

func (a *Alerter) Send(kind, text string) {
	if a == nil || a.dir == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if t, ok := a.last[kind]; ok && time.Since(t) < time.Hour {
		return
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	name := fmt.Sprintf("%d-matrix-bridge-%s.json", time.Now().UnixNano(), hex.EncodeToString(suffix))
	data, _ := json.Marshal(map[string]string{"kind": kind, "text": text})
	tmp := filepath.Join(a.dir, "."+name+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		logf("WARN: could not spool alert %s: %v", kind, err)
		return
	}
	if err := os.Rename(tmp, filepath.Join(a.dir, name)); err != nil {
		logf("WARN: could not spool alert %s: %v", kind, err)
		return
	}
	a.last[kind] = time.Now()
}
