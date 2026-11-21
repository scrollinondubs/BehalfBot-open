package main

import (
	"context"
	"sync"
	"time"
)

// Alerter spools content-free alerts for jill-control, which posts them to
// the unencrypted alerts room, so fixed texts only. One alert per kind per
// hour. The spool belongs to the worker uid, so the file is written by a
// worker process: the bridge itself holds no write access outside its own
// state (round 6 M4).
type Alerter struct {
	worker WorkerSpec
	mu     sync.Mutex
	last   map[string]time.Time
}

func NewAlerter(worker WorkerSpec) *Alerter {
	return &Alerter{worker: worker, last: map[string]time.Time{}}
}

func (a *Alerter) Send(kind, text string) {
	if a == nil || len(a.worker.Argv) == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if t, ok := a.last[kind]; ok && time.Since(t) < time.Hour {
		return
	}
	if _, err := RunWorker(context.Background(), a.worker, "alert", WorkerRequest{AlertKind: kind, Text: text}, 30*time.Second); err != nil {
		logf("WARN: could not spool alert %s: %v", kind, err)
		return
	}
	a.last[kind] = time.Now()
}
