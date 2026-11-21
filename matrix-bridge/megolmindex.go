package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Late delivery (round 6b N2). The homeserver can hold one of Sean's
// messages back and deliver it later with a fresh timestamp. Megolm numbers
// every message of a session, and the number sits inside the authenticated
// ciphertext, so the server cannot change it. The bridge remembers, per
// (sending device's identity key, session), the highest index it accepted,
// persisted across restarts, and drops anything lower: a message that
// arrives after a newer one from the same session was delayed.
//
// Not covered: a held-back message that is the last one of a session Sean's
// client has since replaced. The reply header remains the signal there.

const megolmIndexFile = "megolm-index.json"

type IndexStore struct {
	mu   sync.Mutex
	path string
	max  map[string]uint
}

func OpenIndexStore(dir string) (*IndexStore, error) {
	s := &IndexStore{path: filepath.Join(dir, megolmIndexFile), max: map[string]uint{}}
	err := readJSON(s.path, &s.max)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if s.max == nil {
		s.max = map[string]uint{}
	}
	return s, nil
}

func indexKey(identity id.Curve25519, session id.SessionID) string {
	return identity.String() + "|" + session.String()
}

// Late reports whether index is below one already accepted for the session.
func (s *IndexStore) Late(key string, index uint) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.max[key]
	return ok && index < m
}

// Accept records index as acted on, persisted (fsync) before it returns.
func (s *IndexStore) Accept(key string, index uint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.max[key]; ok && index <= m {
		return nil
	}
	s.max[key] = index
	data, err := json.Marshal(s.max)
	if err != nil {
		return err
	}
	return writeFileSync(s.path, data)
}

type megolmRef struct {
	session id.SessionID
	index   uint
}

// encRecorder remembers the session and index of each encrypted event as it
// arrives, before decryption, so the decrypted event can be checked.
type encRecorder struct {
	mu   sync.Mutex
	refs map[id.EventID]megolmRef
}

func newEncRecorder() *encRecorder { return &encRecorder{refs: map[id.EventID]megolmRef{}} }

func (r *encRecorder) Record(_ context.Context, evt *event.Event) {
	c, ok := evt.Content.Parsed.(*event.EncryptedEventContent)
	if !ok || evt.ID == "" {
		return
	}
	idx, err := crypto.ParseMegolmMessageIndex(c.MegolmCiphertext)
	if err != nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.refs) > 4096 {
		r.refs = map[id.EventID]megolmRef{}
	}
	r.refs[evt.ID] = megolmRef{session: c.SessionID, index: idx}
}

func (r *encRecorder) Take(evtID id.EventID) (megolmRef, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ref, ok := r.refs[evtID]
	delete(r.refs, evtID)
	return ref, ok
}
