//go:build integration

// End-to-end test against a throwaway continuwuity homeserver started by
// selftest/matrix-bridge-e2e.sh. Never point it at a real homeserver: it
// registers users and creates rooms.
//
//	bash selftest/matrix-bridge-e2e.sh
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	e2ePassword = "e2e-throwaway-password-1"
	e2eServer   = "test.local"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func waitUntil(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func register(t *testing.T, ctx context.Context, hs, user, token string) {
	t.Helper()
	cli, _ := mautrix.NewClient(hs, "", "")
	req := &mautrix.ReqRegister[any]{Username: user, Password: e2ePassword, InhibitLogin: true}
	_, uia, err := cli.Register(ctx, req)
	if uia == nil {
		t.Fatalf("register %s: expected an interactive-auth step, got %v", user, err)
	}
	req.Auth = map[string]any{"type": "m.login.registration_token", "token": token, "session": uia.Session}
	if _, _, err := cli.Register(ctx, req); err != nil {
		t.Fatalf("register %s: %v", user, err)
	}
}

func login(t *testing.T, ctx context.Context, hs string, user id.UserID, device string) *Creds {
	t.Helper()
	cli, _ := mautrix.NewClient(hs, "", "")
	resp, err := cli.Login(ctx, &mautrix.ReqLogin{
		Type:       mautrix.AuthTypePassword,
		Identifier: mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: user.String()},
		Password:   e2ePassword, InitialDeviceDisplayName: device,
	})
	if err != nil {
		t.Fatalf("login %s: %v", user, err)
	}
	return &Creds{Homeserver: hs, UserID: resp.UserID, DeviceID: resp.DeviceID, AccessToken: resp.AccessToken}
}

// peer is a plain client (fake Sean): same crypto stack, Element X-like
// sharing policy (cross-signed devices only), messages from Jill collected.
type peer struct {
	cli    *mautrix.Client
	helper *cryptohelper.CryptoHelper
	mu     sync.Mutex
	got    []string
}

func newPeer(t *testing.T, ctx context.Context, hs string, creds *Creds, minTrust id.TrustState) *peer {
	t.Helper()
	cli, helper, err := OpenCrypto(ctx, Config{Homeserver: hs, StateDir: t.TempDir()}, creds)
	if err != nil {
		t.Fatal(err)
	}
	helper.Machine().SendKeysMinTrust = minTrust
	cli.Crypto = helper
	p := &peer{cli: cli, helper: helper}
	cli.Syncer.(*mautrix.DefaultSyncer).OnEventType(event.EventMessage, func(_ context.Context, evt *event.Event) {
		if c, ok := evt.Content.Parsed.(*event.MessageEventContent); ok && evt.Sender != creds.UserID {
			p.mu.Lock()
			p.got = append(p.got, c.Body)
			p.mu.Unlock()
		}
	})
	return p
}

func (p *peer) find(substr string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := len(p.got) - 1; i >= 0; i-- {
		if strings.Contains(p.got[i], substr) {
			return p.got[i]
		}
	}
	return ""
}

// seanSAS accepts Jill's request and confirms the emoji only after the test
// has compared both sides.
type seanSAS struct {
	vh     *verificationhelper.VerificationHelper
	emojis chan []string
	match  chan bool
	done   chan struct{}
	logf   func(string, ...any)
}

func (s *seanSAS) VerificationRequested(ctx context.Context, txn id.VerificationTransactionID, _ id.UserID, _ id.DeviceID) {
	s.logf("sean: verification requested %s", txn)
	go func() {
		if err := s.vh.AcceptVerification(context.WithoutCancel(ctx), txn); err != nil {
			s.logf("sean: accept failed: %v", err)
		}
	}()
}
func (s *seanSAS) VerificationReady(context.Context, id.VerificationTransactionID, id.DeviceID, bool, bool, *verificationhelper.QRCode) {
}
func (s *seanSAS) VerificationCancelled(_ context.Context, _ id.VerificationTransactionID, code event.VerificationCancelCode, reason string) {
	s.logf("sean: verification cancelled %s %s", code, reason)
}
func (s *seanSAS) VerificationDone(context.Context, id.VerificationTransactionID, event.VerificationMethod) {
	close(s.done)
}
func (s *seanSAS) ShowSAS(ctx context.Context, txn id.VerificationTransactionID, emojis []rune, descs []string, _ []int) {
	s.emojis <- FormatEmojis(emojis, descs)
	go func() {
		if <-s.match {
			if err := s.vh.ConfirmSAS(context.WithoutCancel(ctx), txn); err != nil {
				s.logf("sean: confirm failed: %v", err)
			}
		}
	}()
}

// jillTTY answers setup's prompts the way Sean would at the terminal.
type jillTTY struct {
	mu        sync.Mutex
	lastEmoji string
	sean      *seanSAS
}

func (j *jillTTY) Secret(string) (string, error) { return e2ePassword, nil }
func (j *jillTTY) Say(text string) {
	if strings.HasPrefix(text, "    ") && strings.Contains(text, "   ") {
		j.mu.Lock()
		j.lastEmoji = strings.TrimSpace(text)
		j.mu.Unlock()
	}
}
func (j *jillTTY) Line(prompt string) (string, error) {
	if !strings.Contains(prompt, "identical") {
		return "", nil
	}
	select {
	case theirs := <-j.sean.emojis:
		j.mu.Lock()
		mine := j.lastEmoji
		j.mu.Unlock()
		ok := mine != "" && mine == strings.Join(theirs, "   ")
		j.sean.match <- ok
		if ok {
			return "yes", nil
		}
		return "no", nil
	case <-time.After(2 * time.Minute):
		return "no", nil
	}
}

func stubOpencode(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	json200 := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			h(w, r)
		}
	}
	mux.HandleFunc("POST /session", json200(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"id":"ses_e2e"}`)
	}))
	mux.HandleFunc("GET /session/ses_e2e", json200(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) }))
	mux.HandleFunc("GET /global/health", json200(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) }))
	mux.HandleFunc("POST /session/ses_e2e/message", json200(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Parts []struct{ Text string } `json:"parts"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		text := ""
		if len(body.Parts) > 0 {
			lines := strings.Split(strings.TrimSpace(body.Parts[0].Text), "\n")
			text = lines[len(lines)-1]
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"parts": []map[string]string{{"type": "text", "text": "stub-reply: " + text}}})
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestE2E(t *testing.T) {
	hs := os.Getenv("IT_HS_URL")
	if hs == "" {
		t.Skip("IT_HS_URL not set; run selftest/matrix-bridge-e2e.sh")
	}
	sasTimeout = 2 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	logs := &lockedBuf{}
	log.SetOutput(io.MultiWriter(os.Stderr, logs))
	defer log.SetOutput(os.Stderr)

	waitUntil(t, time.Minute, "the homeserver", func() bool {
		resp, err := http.Get(hs + "/_matrix/client/versions")
		if err == nil {
			resp.Body.Close()
		}
		return err == nil && resp.StatusCode == 200
	})
	register(t, ctx, hs, "admin", os.Getenv("IT_FIRST_TOKEN"))
	for _, u := range []string{"sean", "jill"} {
		register(t, ctx, hs, u, os.Getenv("IT_TOKEN"))
	}
	seanID, jillID := id.NewUserID("sean", e2eServer), id.NewUserID("jill", e2eServer)

	// Fake Sean: cross-signed phone, Element X-like sharing policy.
	sean := newPeer(t, ctx, hs, login(t, ctx, hs, seanID, "sean-phone"), id.TrustStateCrossSignedTOFU)
	smach := sean.helper.Machine()
	if _, _, err := smach.GenerateAndUploadCrossSigningKeysWithPassword(ctx, e2ePassword, ""); err != nil {
		t.Fatal(err)
	}
	if err := smach.SignOwnDevice(ctx, smach.OwnIdentity()); err != nil {
		t.Fatal(err)
	}
	if err := smach.SignOwnMasterKey(ctx); err != nil {
		t.Fatal(err)
	}
	created, err := sean.cli.CreateRoom(ctx, &mautrix.ReqCreateRoom{
		Preset: "private_chat", Invite: []id.UserID{jillID},
		InitialState: []*event.Event{{Type: event.StateEncryption, Content: event.Content{
			Parsed: &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	room := created.RoomID
	sas := &seanSAS{emojis: make(chan []string, 1), match: make(chan bool, 1), done: make(chan struct{}), logf: t.Logf}
	FixInRoomVerificationIDs(sean.cli.Syncer.(mautrix.ExtensibleSyncer), room, jillID)
	sas.vh = verificationhelper.NewVerificationHelper(sean.cli, smach, nil, sas, false, false, true)
	if err := sas.vh.Init(ctx); err != nil {
		t.Fatal(err)
	}
	go func() { _ = sean.cli.SyncWithContext(ctx) }()

	// Stub opencode + the real Python worker.
	work := t.TempDir()
	snapDir := filepath.Join(work, "agentmail-gw", "drafts")
	for _, d := range []string{snapDir, filepath.Join(work, "control"), filepath.Join(work, "spool")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("OPENCODE_SERVER_URL", stubOpencode(t).URL)
	t.Setenv("ALERT_SPOOL_DIR", filepath.Join(work, "spool"))
	t.Setenv("MATRIX_PRINCIPAL", seanID.String())
	t.Setenv("CONTROL_DIR", filepath.Join(work, "control"))
	t.Setenv("APPROVALS_DIR", filepath.Join(work, "approvals"))
	t.Setenv("SNAPSHOT_DIR", snapDir)
	t.Setenv("WORKER_STATE_DIR", filepath.Join(work, "worker"))
	t.Setenv("BRIDGE_SESSIONS_FILE", filepath.Join(work, "worker", "sessions.json"))
	draftID := "d_e2e_fixture"
	key := sha256.Sum256([]byte("draft\x00" + draftID))
	fixture := `{"draft_id":"` + draftID + `","content":{"to":["alice@example.com"],"bcc":["hidden@evil.example"],"subject":"Invoice‮gpj.exe","text":"Hi Alice\nsha256 0000"}}`
	if err := os.WriteFile(filepath.Join(snapDir, hex.EncodeToString(key[:])+".json"), []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	worker, _ := filepath.Abs("../bridge/matrix_worker.py")

	cfg := Config{
		Homeserver: hs, Principal: seanID, Room: room, JillUser: jillID,
		StateDir: filepath.Join(work, "jill-state"),
		Worker:   WorkerSpec{Argv: []string{"python3", "-I", worker}}, ChatWorker: WorkerSpec{Argv: []string{"python3", "-I", worker}}, MaxAttach: 1 << 20, ReadyFile: filepath.Join(work, "ready"),
	}

	// 1. Setup: login, cross-signing, SAS with Sean, pin.
	if err := Setup(ctx, cfg, &jillTTY{sean: sas}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	select {
	case <-sas.done:
	case <-time.After(30 * time.Second):
		t.Fatal("Sean's side never finished the verification")
	}
	pin, err := LoadPin(cfg.StateDir, seanID)
	if err != nil || pin.MasterKey != smach.CrossSigningKeys.MasterKey.PublicKey() {
		t.Fatalf("pin %v does not hold Sean's master key (%v)", pin.MasterKey, err)
	}

	// 2. The bridge.
	b, err := NewBridge(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = b.cli.SyncWithContext(ctx) }()
	waitUntil(t, time.Minute, "the bridge's first sync", func() bool { _, err := os.Stat(cfg.ReadyFile); return err == nil })
	if b.locked.Load() {
		t.Fatal("bridge is identity-locked after a successful setup")
	}

	say := func(text string) id.EventID {
		t.Helper()
		resp, err := sean.cli.SendMessageEvent(ctx, room, event.EventMessage, &event.MessageEventContent{MsgType: event.MsgText, Body: text})
		if err != nil {
			t.Fatalf("send %q: %v", text, err)
		}
		return resp.EventID
	}
	expect := func(substr string) string {
		t.Helper()
		var got string
		waitUntil(t, 90*time.Second, "a reply containing "+substr, func() bool { got = sean.find(substr); return got != "" })
		return got
	}

	// 3. Encrypted round trip through the bridge and the stub model.
	hello := say("hello jill, round trip")
	reply := expect("stub-reply: hello jill, round trip")
	if !strings.HasPrefix(reply, `Jill, re "hello jill, round trip" (received `) {
		t.Fatalf("model reply does not open with the quote and receive time:\n%s", reply)
	}
	if !strings.Contains(logs.String(), "accept event="+hello.String()) {
		t.Fatal("no accept line for the round trip")
	}

	// 4. Approval screen and approve with a fixture snapshot. A message that
	// carries a live code never reaches the model, and voids the code
	// (round 6b N1).
	say("show draft " + draftID)
	first := expect("DRAFT \"" + draftID + "\"")
	if !strings.HasPrefix(first, "[bridge] DRAFT") {
		t.Fatalf("bridge output is not marked:\n%s", first)
	}
	pasted := regexp.MustCompile(`approve draft \S+ [0-9a-f]{64} (\S+)`).FindStringSubmatch(first)
	if pasted == nil {
		t.Fatal("no code on the first screen")
	}
	say("is this right? " + pasted[1])
	expect("not sent to Jill")
	say("show draft " + draftID)
	waitUntil(t, 60*time.Second, "a second screen", func() bool {
		s := sean.find("DRAFT \"" + draftID + "\"")
		return s != "" && !strings.Contains(s, pasted[1])
	})
	screen := sean.find("DRAFT \"" + draftID + "\"")
	lines := strings.Split(strings.TrimSpace(screen), "\n")
	last := lines[len(lines)-1]
	if !strings.HasPrefix(last, "sha256 ") || !strings.Contains(screen, `"hidden@evil.example"`) || !strings.Contains(screen, `\u{202e}`) {
		t.Fatalf("approval screen incomplete:\n%s", screen)
	}
	sha := strings.TrimPrefix(last, "sha256 ")
	code := regexp.MustCompile(`approve draft \S+ [0-9a-f]{64} (\S+)`).FindStringSubmatch(screen)
	if code == nil {
		t.Fatalf("no approval code on the screen:\n%s", screen)
	}
	say("approve draft " + draftID + " " + sha + " " + code[1])
	challenge := expect("send `confirm ")
	if m, _ := filepath.Glob(filepath.Join(work, "approvals", "draft", "*.json")); len(m) != 0 {
		t.Fatal("an approval was written before `confirm`")
	}
	say("confirm " + confirmCode(t, challenge))
	expect("Approved draft " + draftID)
	matches, _ := filepath.Glob(filepath.Join(work, "approvals", "draft", "*.json"))
	if len(matches) != 1 {
		t.Fatalf("expected one approval file, got %v", matches)
	}
	if data, _ := os.ReadFile(matches[0]); !strings.Contains(string(data), sha) {
		t.Fatal("approval is not bound to the typed sha256")
	}

	// 4b. halt, then resume needs a confirm on the bridge's clock.
	haltFile := filepath.Join(work, "control", "halt.json")
	say("halt")
	expect("HALTED")
	say("resume")
	resumeChallenge := expect("lift the halt")
	if data, _ := os.ReadFile(haltFile); !strings.Contains(string(data), `"enabled": true`) {
		t.Fatal("resume without confirm lifted the halt")
	}
	say("confirm " + confirmCode(t, resumeChallenge))
	expect("RESUMED")

	// 5. Replay: the server delivers the round-trip event again.
	raw, err := b.cli.GetEvent(ctx, room, hello)
	if err != nil {
		t.Fatal(err)
	}
	raw.RoomID = room
	if err := raw.Content.ParseRaw(raw.Type); err != nil {
		t.Fatal(err)
	}
	b.enc.Record(ctx, raw)
	dec, err := b.helper.Decrypt(ctx, raw)
	if err != nil {
		t.Fatalf("decrypting the replayed event: %v", err)
	}
	dec.Mautrix.EventSource |= event.SourceDecrypted
	b.onDecrypted(ctx, dec)
	// Dropped either as a replay (event id) or, since newer messages from the
	// same Megolm session were accepted after it, as a late delivery.
	if !strings.Contains(logs.String(), "drop event="+hello.String()+" reason=replay") &&
		!strings.Contains(logs.String(), "drop event="+hello.String()+" reason="+ReasonLate) {
		t.Fatal("replayed event was not dropped")
	}

	// 6. A second, non-cross-signed device on Sean's account.
	rogue := newPeer(t, ctx, hs, login(t, ctx, hs, seanID, "unverified-session"), id.TrustStateUnset)
	if _, err := rogue.cli.State(ctx, room); err != nil {
		t.Fatal(err)
	}
	if _, err := rogue.helper.Machine().FetchKeys(ctx, []id.UserID{seanID, jillID}, true); err != nil {
		t.Fatal(err)
	}
	rogueResp, err := rogue.cli.SendMessageEvent(ctx, room, event.EventMessage, &event.MessageEventContent{MsgType: event.MsgText, Body: "rogue device asks for the taxes"})
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 90*time.Second, "the rogue device's message to be dropped", func() bool {
		return strings.Contains(logs.String(), fmt.Sprintf("drop event=%s reason=%s", rogueResp.EventID, ReasonNotSigned))
	})
	time.Sleep(3 * time.Second)
	if sean.find("taxes") != "" {
		t.Fatal("the bridge answered the rogue device")
	}
}

func confirmCode(t *testing.T, text string) string {
	t.Helper()
	m := regexp.MustCompile("confirm ([a-z0-9]{10})").FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("no confirm code in %q", text)
	}
	return m[1]
}
