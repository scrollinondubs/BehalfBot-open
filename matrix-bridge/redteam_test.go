//go:build integration

// Red-team round 6 regressions (Fable's RT1-RT4, /Users/jax/work/jill-v2-
// redteam-60.md), adapted to pass only while the fixes hold. Run with
// selftest/matrix-bridge-e2e.sh against a THROWAWAY homeserver on
// 127.0.0.1:18448.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var rtAdminOnce sync.Once

type rtPrompter struct {
	inner    *jillTTY
	mu       sync.Mutex
	said     []string
	recovery string
	wantRec  bool
}

func (p *rtPrompter) Secret(prompt string) (string, error) {
	if strings.Contains(prompt, "recovery key") {
		return p.recovery, nil
	}
	return e2ePassword, nil
}
func (p *rtPrompter) Say(text string) {
	p.mu.Lock()
	p.said = append(p.said, text)
	if p.wantRec && strings.TrimSpace(text) != "" {
		p.recovery, p.wantRec = strings.TrimSpace(text), false
	}
	if strings.Contains(text, "JILL'S RECOVERY KEY") {
		p.wantRec = true
	}
	p.mu.Unlock()
	p.inner.Say(text)
}
func (p *rtPrompter) Line(prompt string) (string, error) {
	if strings.Contains(prompt, "matches exactly") {
		return "yes", nil
	}
	return p.inner.Line(prompt)
}
func (p *rtPrompter) all() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.said, "\n")
}

type rtEnv struct {
	hs             string
	seanID, jillID id.UserID
	sean           *peer
	sas            *seanSAS
	room           id.RoomID
	cfg            Config
	work           string
	logs           *lockedBuf
	tty            *rtPrompter
}

func rtBase(t *testing.T, ctx context.Context, tag, jillHS string) *rtEnv {
	hs := os.Getenv("IT_HS_URL")
	if hs == "" || !strings.Contains(hs, "127.0.0.1:18448") {
		t.Skip("throwaway homeserver only")
	}
	if jillHS == "" {
		jillHS = hs
	}
	e := &rtEnv{hs: hs, logs: &lockedBuf{}}
	log.SetOutput(io.MultiWriter(os.Stderr, e.logs))
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	rtAdminOnce.Do(func() {
		cli, _ := mautrix.NewClient(hs, "", "")
		req := &mautrix.ReqRegister[any]{Username: "admin", Password: e2ePassword, InhibitLogin: true}
		if _, uia, _ := cli.Register(ctx, req); uia != nil {
			req.Auth = map[string]any{"type": "m.login.registration_token", "token": os.Getenv("IT_FIRST_TOKEN"), "session": uia.Session}
			_, _, _ = cli.Register(ctx, req)
		}
	})
	for _, u := range []string{"sean" + tag, "jill" + tag} {
		register(t, ctx, hs, u, os.Getenv("IT_TOKEN"))
	}
	e.seanID, e.jillID = id.NewUserID("sean"+tag, e2eServer), id.NewUserID("jill"+tag, e2eServer)
	e.sean = newPeer(t, ctx, hs, login(t, ctx, hs, e.seanID, "sean-phone"), id.TrustStateCrossSignedTOFU)
	rtIdentity(t, ctx, e.sean)
	created, err := e.sean.cli.CreateRoom(ctx, &mautrix.ReqCreateRoom{
		Preset: "private_chat", Invite: []id.UserID{e.jillID},
		InitialState: []*event.Event{{Type: event.StateEncryption, Content: event.Content{
			Parsed: &event.EncryptionEventContent{Algorithm: id.AlgorithmMegolmV1}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.room = created.RoomID
	e.sas = &seanSAS{emojis: make(chan []string, 1), match: make(chan bool, 1), done: make(chan struct{}), logf: t.Logf}
	FixInRoomVerificationIDs(e.sean.cli.Syncer.(mautrix.ExtensibleSyncer), e.room, e.jillID)
	e.sas.vh = verificationhelper.NewVerificationHelper(e.sean.cli, e.sean.helper.Machine(), nil, e.sas, false, false, true)
	if err := e.sas.vh.Init(ctx); err != nil {
		t.Fatal(err)
	}
	go func() { _ = e.sean.cli.SyncWithContext(ctx) }()

	e.work = t.TempDir()
	for _, d := range []string{"agentmail-gw/drafts", "control", "spool"} {
		if err := os.MkdirAll(filepath.Join(e.work, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("OPENCODE_SERVER_URL", stubOpencode(t).URL)
	t.Setenv("ALERT_SPOOL_DIR", filepath.Join(e.work, "spool"))
	t.Setenv("MATRIX_PRINCIPAL", e.seanID.String())
	t.Setenv("CONTROL_DIR", filepath.Join(e.work, "control"))
	t.Setenv("APPROVALS_DIR", filepath.Join(e.work, "approvals"))
	t.Setenv("SNAPSHOT_DIR", filepath.Join(e.work, "agentmail-gw", "drafts"))
	t.Setenv("WORKER_STATE_DIR", filepath.Join(e.work, "worker"))
	t.Setenv("BRIDGE_SESSIONS_FILE", filepath.Join(e.work, "worker", "sessions.json"))
	worker, _ := filepath.Abs("../bridge/matrix_worker.py")
	e.cfg = Config{
		Homeserver: jillHS, Principal: e.seanID, Room: e.room, JillUser: e.jillID,
		StateDir: filepath.Join(e.work, "jill-state"),
		Worker:   WorkerSpec{Argv: []string{"python3", "-I", worker}}, ChatWorker: WorkerSpec{Argv: []string{"python3", "-I", worker}}, MaxAttach: 1 << 20, ReadyFile: filepath.Join(e.work, "ready"),
	}
	e.tty = &rtPrompter{inner: &jillTTY{sean: e.sas}}
	return e
}

func rtIdentity(t *testing.T, ctx context.Context, p *peer) id.Ed25519 {
	t.Helper()
	m := p.helper.Machine()
	if _, _, err := m.GenerateAndUploadCrossSigningKeys(ctx, func(ui *mautrix.RespUserInteractive) any {
		return map[string]any{"type": "m.login.password", "session": ui.Session, "password": e2ePassword,
			"identifier": map[string]any{"type": "m.id.user", "user": p.cli.UserID.String()}}
	}, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.SignOwnDevice(ctx, m.OwnIdentity()); err != nil {
		t.Fatal(err)
	}
	if err := m.SignOwnMasterKey(ctx); err != nil {
		t.Fatal(err)
	}
	return m.CrossSigningKeys.MasterKey.PublicKey()
}

func (e *rtEnv) bridge(t *testing.T, ctx context.Context) *Bridge {
	t.Helper()
	b, err := NewBridge(ctx, e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = b.cli.SyncWithContext(ctx) }()
	waitUntil(t, time.Minute, "the bridge's first sync", func() bool { _, err := os.Stat(e.cfg.ReadyFile); return err == nil })
	return b
}

func (e *rtEnv) say(t *testing.T, ctx context.Context, p *peer, text string) id.EventID {
	t.Helper()
	resp, err := p.cli.SendMessageEvent(ctx, e.room, event.EventMessage, &event.MessageEventContent{MsgType: event.MsgText, Body: text})
	if err != nil {
		t.Fatalf("send %q: %v", text, err)
	}
	return resp.EventID
}

func (e *rtEnv) waitLog(t *testing.T, d time.Duration, s string) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if strings.Contains(e.logs.String(), s) {
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

// --- RT1: freshness rests on origin_server_ts, which the server writes ------

var tsRe = regexp.MustCompile(`"origin_server_ts":(\d+)`)

func lyingServer(t *testing.T, upstream string, shiftMS *atomic.Int64) string {
	u, _ := url.Parse(upstream)
	rp := httputil.NewSingleHostReverseProxy(u)
	dir := rp.Director
	rp.Director = func(r *http.Request) { dir(r); r.Header.Del("Accept-Encoding") }
	rp.ModifyResponse = func(resp *http.Response) error {
		if !strings.Contains(resp.Request.URL.Path, "/sync") {
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		if s := shiftMS.Load(); s != 0 {
			body = tsRe.ReplaceAllFunc(body, func(m []byte) []byte {
				n, _ := strconv.ParseInt(string(tsRe.FindSubmatch(m)[1]), 10, 64)
				return []byte(fmt.Sprintf(`"origin_server_ts":%d`, n+s))
			})
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return nil
	}
	srv := httptest.NewServer(rp)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestRT1HeldBackResumeOnlyGetsAChallenge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sasTimeout = 2 * time.Minute
	var shift atomic.Int64
	hs := os.Getenv("IT_HS_URL")
	if hs == "" {
		t.Skip()
	}
	e := rtBase(t, ctx, "rt1", lyingServer(t, hs, &shift))
	if err := Setup(ctx, e.cfg, e.tty); err != nil {
		t.Fatalf("setup: %v", err)
	}
	b := e.bridge(t, ctx)
	// The bridge's clock runs one hour ahead: every message Sean sends "now"
	// is, from the bridge's side, a message he sent an hour ago.
	b.now = func() time.Time { return time.Now().Add(time.Hour) }
	halt := filepath.Join(e.work, "control", "halt.json")
	_ = os.WriteFile(halt, []byte(`{"enabled":true,"enabled_at":"2026-01-01T00:00:00Z","enabled_by":"sean","auto_lift_after":null,"reason":"incident"}`), 0o644)

	ev1 := e.say(t, ctx, e.sean, "resume")
	if !e.waitLog(t, 30*time.Second, "drop event="+ev1.String()+" reason=stale") {
		t.Fatalf("control: hour-old resume with an honest timestamp was not dropped as stale")
	}
	// The attack: the server delivers the held-back `resume` stamped fresh.
	shift.Store(3600 * 1000)
	ev2 := e.say(t, ctx, e.sean, "resume")
	if !e.waitLog(t, 30*time.Second, "accept event="+ev2.String()) {
		t.Fatalf("rewritten timestamp was not accepted; this test no longer exercises the attack")
	}
	waitUntil(t, 30*time.Second, "the challenge", func() bool { return e.sean.find("lift the halt") != "" })
	time.Sleep(3 * time.Second)
	if data, _ := os.ReadFile(halt); !strings.Contains(string(data), `"enabled":true`) && !strings.Contains(string(data), `"enabled": true`) {
		t.Fatalf("FIX REGRESSED (round 6 H3): a held-back `resume` lifted the halt:\n%s", data)
	}
}

// --- RT2: who holds the room key after a failed SAS setup and a --no-sas re-pin ---

func TestRT2SetupSessionLeak(t *testing.T) {
	tag := "rt2"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	e := rtBase(t, ctx, tag, "")
	// The homeserver admin swaps Sean's cross-signing identity for its own
	// and adds a device signed by it (in the test: a second login on Sean's
	// account that uploads new cross-signing keys).
	planted := newPeer(t, ctx, e.hs, login(t, ctx, e.hs, e.seanID, "admin-planted"), id.TrustStateCrossSignedTOFU)
	fake := rtIdentity(t, ctx, planted)
	if _, err := planted.cli.State(ctx, e.room); err != nil {
		t.Fatal(err)
	}
	go func() { _ = planted.cli.SyncWithContext(ctx) }()

	// Setup attempt 1 (SAS): nobody on Sean's real phone sees a request; it times out.
	sasTimeout = 15 * time.Second
	err := Setup(ctx, e.cfg, e.tty)
	t.Logf("setup attempt 1 (under attack): %v", err)
	if err == nil {
		t.Fatal("setup 1 unexpectedly succeeded")
	}
	if p, _ := LoadPin(e.cfg.StateDir, e.seanID); p.MasterKey != "" {
		t.Fatal("something was pinned")
	}
	// The admin puts things back: Sean's account shows Sean's own identity again.
	realKey := rtIdentity(t, ctx, e.sean)
	if realKey == fake {
		t.Fatal("bad test")
	}
	// Setup attempt 2, the documented fallback: Sean compares the fingerprint, it IS his.
	e.cfg.NoSAS = true
	if err := Setup(ctx, e.cfg, e.tty); err != nil {
		t.Fatalf("setup 2 (--no-sas): %v", err)
	}
	if !strings.Contains(e.tty.all(), Fingerprint(realKey)) {
		t.Fatal("setup 2 did not show Sean's real key")
	}
	pin, _ := LoadPin(e.cfg.StateDir, e.seanID)
	if pin.MasterKey != realKey {
		t.Fatalf("pin is not Sean's real key")
	}
	t.Logf("setup 2 pinned Sean's REAL master key %s", Fingerprint(realKey))
	b := e.bridge(t, ctx)
	if b.locked.Load() {
		t.Fatal("locked")
	}
	ev := e.say(t, ctx, e.sean, "summarise my tax return")
	if !e.waitLog(t, 60*time.Second, "accept event="+ev.String()) {
		t.Fatalf("bridge did not accept Sean's message")
	}
	waitUntil(t, 60*time.Second, "Sean to read the reply", func() bool {
		return e.sean.find("stub-reply: summarise my tax return") != ""
	})
	time.Sleep(5 * time.Second)
	if leak := planted.find("stub-reply"); leak != "" {
		t.Fatalf("FIX REGRESSED (round 6 H1): the admin-planted device read Jill's reply: %q", leak)
	}
}

// --- RT3: planted device on Jill's own account, and Jill's identity replaced ---

func TestRT3PlantedJillDevice(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sasTimeout = 2 * time.Minute
	e := rtBase(t, ctx, "rt3", "")
	if err := Setup(ctx, e.cfg, e.tty); err != nil {
		t.Fatalf("setup: %v", err)
	}
	b := e.bridge(t, ctx)
	hello := e.say(t, ctx, e.sean, "hello one")
	waitUntil(t, 60*time.Second, "round trip", func() bool { return e.sean.find("stub-reply: hello one") != "" })

	// Replay 1: same ciphertext under a new event id (the server mints ids).
	fetch := func() *event.Event {
		raw, err := b.cli.GetEvent(ctx, e.room, hello)
		if err != nil {
			t.Fatal(err)
		}
		raw.RoomID = e.room
		if err := raw.Content.ParseRaw(raw.Type); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	forged := fetch()
	forged.ID = "$forgedReplayEventId0000000000000000000000000"
	forged.Timestamp = time.Now().UnixMilli()
	_, derr := b.helper.Decrypt(ctx, forged)
	t.Logf("replay under a NEW event id and fresh timestamp: decrypt error = %v", derr)
	if derr == nil {
		t.Fatalf("REPLAY ACCEPTED under a new event id")
	}
	// Replay 2: a restarted bridge (new process state, same state volume) gets the original event again.
	b2, err := NewBridge(ctx, e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	again := fetch()
	b2.enc.Record(ctx, again)
	dec, err := b2.helper.Decrypt(ctx, again)
	if err != nil {
		t.Fatalf("restart replay decrypt: %v", err)
	}
	dec.Mautrix.EventSource |= event.SourceDecrypted
	b2.onDecrypted(ctx, dec)
	if !e.waitLog(t, 10*time.Second, "drop event="+hello.String()+" reason=replay") {
		t.Fatalf("REPLAY ACCEPTED after restart")
	}
	t.Logf("replay of the original event into a restarted bridge: dropped as replay")
	b2.helper.Close()

	j2 := newPeer(t, ctx, e.hs, login(t, ctx, e.hs, e.jillID, "admin-planted-on-jill"), id.TrustStateUnset)
	var mu sync.Mutex
	var seen []string
	j2.cli.Syncer.(*mautrix.DefaultSyncer).OnEventType(event.EventMessage, func(_ context.Context, evt *event.Event) {
		if c, ok := evt.Content.Parsed.(*event.MessageEventContent); ok {
			mu.Lock()
			seen = append(seen, c.Body)
			mu.Unlock()
		}
	})
	got := func(s string) bool {
		mu.Lock()
		defer mu.Unlock()
		for _, x := range seen {
			if strings.Contains(x, s) {
				return true
			}
		}
		return false
	}
	if _, err := j2.cli.State(ctx, e.room); err != nil {
		t.Fatal(err)
	}
	go func() { _ = j2.cli.SyncWithContext(ctx) }()
	mach := b.helper.Machine()
	probe := func(label string) {
		time.Sleep(3 * time.Second) // let the device list change reach the bridge
		if _, err := mach.FetchKeys(ctx, []id.UserID{e.jillID, e.seanID}, true); err != nil {
			t.Fatal(err)
		}
		// Simulate the normal session rotation (100 messages / 7 days).
		if err := mach.CryptoStore.RemoveOutboundGroupSession(ctx, e.room); err != nil {
			t.Fatal(err)
		}
		sent := b.send(ctx, "probe-"+label)
		time.Sleep(6 * time.Second)
		t.Logf("%s: bridge send ok=%v; planted Jill device decrypted it=%v; Sean decrypted it=%v", label, sent, got("probe-"+label), e.sean.find("probe-"+label) != "")
	}
	probe("unsigned-device")
	rtIdentity(t, ctx, j2) // the admin replaces Jill's cross-signing identity and signs its device
	probe("replaced-identity")
	if got("probe-unsigned-device") || got("probe-replaced-identity") {
		t.Fatalf("LEAK: a planted device on Jill's account read the bridge's messages")
	}
	// Positive control: with the trust floor removed the same device must be able to read.
	mach.SendKeysMinTrust = id.TrustStateUnset
	probe("control-no-trust-floor")
	if !got("probe-control-no-trust-floor") {
		t.Fatalf("positive control failed: the planted device could not read even without a trust floor, so the negatives prove nothing")
	}
}

// --- RT4: a third user present during setup keeps the room key -------------

func hideLeave(t *testing.T, upstream string, hidden id.UserID) string {
	u, _ := url.Parse(upstream)
	rp := httputil.NewSingleHostReverseProxy(u)
	dir := rp.Director
	rp.Director = func(r *http.Request) { dir(r); r.Header.Del("Accept-Encoding") }
	rp.ModifyResponse = func(resp *http.Response) error {
		if !strings.Contains(resp.Request.URL.Path, "/sync") {
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var doc any
		if dec.Decode(&doc) != nil {
			resp.Body = io.NopCloser(bytes.NewReader(body))
			return nil
		}
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(dropLeave(doc, hidden.String()))
		body = buf.Bytes()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return nil
	}
	srv := httptest.NewServer(rp)
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestRT4ThirdMemberAtSetup(t *testing.T)       { rt4(t, "rt4", true) }
func TestRT4bThirdMemberHonestServer(t *testing.T) { rt4(t, "rt4b", false) }

func rt4(t *testing.T, tag string, lie bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sasTimeout = 2 * time.Minute
	hs := os.Getenv("IT_HS_URL")
	if hs == "" {
		t.Skip()
	}
	eveID := id.NewUserID("eve"+tag, e2eServer)
	jillHS := ""
	if lie {
		jillHS = hideLeave(t, hs, eveID)
	}
	e := rtBase(t, ctx, tag, jillHS)
	register(t, ctx, hs, "eve"+tag, os.Getenv("IT_TOKEN"))
	eve := newPeer(t, ctx, hs, login(t, ctx, hs, eveID, "third-party"), id.TrustStateUnset)
	rtIdentity(t, ctx, eve)
	if _, err := e.sean.cli.InviteUser(ctx, e.room, &mautrix.ReqInviteUser{UserID: eveID}); err != nil {
		t.Fatal(err)
	}
	if _, err := eve.cli.JoinRoomByID(ctx, e.room); err != nil {
		t.Fatal(err)
	}
	eveCtx, stopEve := context.WithCancel(ctx)
	go func() { _ = eve.cli.SyncWithContext(eveCtx) }()

	// The fix: setup refuses while anyone but Jill and Sean is in the room,
	// before any key is shared.
	err := Setup(ctx, e.cfg, e.tty)
	if err == nil || !strings.Contains(err.Error(), "must hold exactly") {
		t.Fatalf("FIX REGRESSED (round 6 H1): setup ran with a third member present: %v", err)
	}
	if p, _ := LoadPin(e.cfg.StateDir, e.seanID); p.MasterKey != "" {
		t.Fatal("something was pinned")
	}
	if _, err := e.sean.cli.KickUser(ctx, e.room, &mautrix.ReqKickUser{UserID: eveID}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if err := Setup(ctx, e.cfg, e.tty); err != nil {
		t.Fatalf("setup after the third member left: %v", err)
	}
	time.Sleep(3 * time.Second)
	stopEve()

	b := e.bridge(t, ctx)
	ev := e.say(t, ctx, e.sean, "what is in my medical file")
	if !e.waitLog(t, 60*time.Second, "accept event="+ev.String()) {
		t.Fatalf("bridge did not accept")
	}
	waitUntil(t, 60*time.Second, "Sean to read the reply", func() bool { return e.sean.find("stub-reply: what is in my medical file") != "" })

	// Every message Jill ever sent in the room, tried with Eve's keys.
	msgs, err := e.sean.cli.Messages(ctx, e.room, "", "", mautrix.DirectionBackward, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs.Chunk {
		if m.Sender != b.cli.UserID || m.Type != event.EventEncrypted {
			continue
		}
		m.RoomID = e.room
		if err := m.Content.ParseRaw(m.Type); err != nil {
			continue
		}
		if dec, err := eve.helper.Decrypt(ctx, m); err == nil {
			t.Fatalf("FIX REGRESSED (round 6 H1), lying server=%v: the removed third party decrypted a message from Jill: %v",
				lie, dec.Content.Raw)
		}
	}
}

func dropLeave(v any, hidden string) any {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			x[k] = dropLeave(c, hidden)
		}
		return x
	case []any:
		out := make([]any, 0, len(x))
		for _, c := range x {
			if m, ok := c.(map[string]any); ok && m["type"] == "m.room.member" && m["state_key"] == hidden {
				if content, ok := m["content"].(map[string]any); ok && content["membership"] == "leave" {
					continue
				}
			}
			out = append(out, dropLeave(c, hidden))
		}
		return out
	}
	return v
}

// --- Round 6b N2: a held-back message delivered after a newer one --------

// holdBack drops the principal's encrypted timeline events from the
// bridge's /sync while hold is set; to-device room keys still pass. The
// test then delivers the held events itself, in the order it chooses.
func holdBack(t *testing.T, upstream string, sender id.UserID, hold *atomic.Bool) string {
	u, _ := url.Parse(upstream)
	rp := httputil.NewSingleHostReverseProxy(u)
	dir := rp.Director
	rp.Director = func(r *http.Request) { dir(r); r.Header.Del("Accept-Encoding") }
	rp.ModifyResponse = func(resp *http.Response) error {
		if !strings.Contains(resp.Request.URL.Path, "/sync") || !hold.Load() {
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var doc any
		if dec.Decode(&doc) == nil {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(dropEncryptedFrom(doc, sender.String()))
			body = buf.Bytes()
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
		return nil
	}
	srv := httptest.NewServer(rp)
	t.Cleanup(srv.Close)
	return srv.URL
}

func dropEncryptedFrom(v any, sender string) any {
	switch x := v.(type) {
	case map[string]any:
		for k, c := range x {
			x[k] = dropEncryptedFrom(c, sender)
		}
		return x
	case []any:
		out := make([]any, 0, len(x))
		for _, c := range x {
			if m, ok := c.(map[string]any); ok && m["type"] == "m.room.encrypted" && m["sender"] == sender && m["event_id"] != nil {
				continue
			}
			out = append(out, dropEncryptedFrom(c, sender))
		}
		return out
	}
	return v
}

func TestN2LateDelivery(t *testing.T)              { n2(t, "n2a", false) }
func TestN2LateDeliveryAcrossRestart(t *testing.T) { n2(t, "n2b", true) }

func n2(t *testing.T, tag string, restart bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	sasTimeout = 2 * time.Minute
	hs := os.Getenv("IT_HS_URL")
	if hs == "" {
		t.Skip()
	}
	var hold atomic.Bool
	seanID := id.NewUserID("sean"+tag, e2eServer)
	e := rtBase(t, ctx, tag, holdBack(t, hs, seanID, &hold))
	if err := Setup(ctx, e.cfg, e.tty); err != nil {
		t.Fatalf("setup: %v", err)
	}
	b := e.bridge(t, ctx)

	// The server holds both back; Sean sent the first one first.
	hold.Store(true)
	lateHalt := e.say(t, ctx, e.sean, e.jillID.String()+": halt")
	older := e.say(t, ctx, e.sean, "yes, go ahead and do it")
	newer := e.say(t, ctx, e.sean, "what is on my calendar today")
	time.Sleep(3 * time.Second) // the room key reaches the bridge by to-device

	deliver := func(to *Bridge, evtID id.EventID) {
		t.Helper()
		var dec *event.Event
		waitUntil(t, 30*time.Second, "the bridge to decrypt "+evtID.String(), func() bool {
			raw, err := to.cli.GetEvent(ctx, e.room, evtID)
			if err != nil {
				return false
			}
			raw.RoomID = e.room
			if raw.Content.ParseRaw(raw.Type) != nil {
				return false
			}
			to.enc.Record(ctx, raw)
			dec, err = to.helper.Decrypt(ctx, raw)
			return err == nil
		})
		dec.Mautrix.EventSource |= event.SourceDecrypted
		to.onDecrypted(ctx, dec)
	}

	deliver(b, newer)
	if !e.waitLog(t, 30*time.Second, "accept event="+newer.String()) {
		t.Fatal("the newer message was not accepted")
	}
	target := b
	if restart {
		b2, err := NewBridge(ctx, e.cfg)
		if err != nil {
			t.Fatal(err)
		}
		target = b2
	}
	deliver(target, older)
	if !e.waitLog(t, 30*time.Second, "drop event="+older.String()+" reason="+ReasonLate) {
		t.Fatalf("FIX REGRESSED (round 6b N2, restart=%v): a held-back older message was not dropped as late", restart)
	}
	waitUntil(t, 60*time.Second, "the late-delivery notice", func() bool {
		return e.sean.find(`An older message arrived late and was not sent to Jill: "yes, go ahead and do it"`) != ""
	})
	if e.sean.find("stub-reply: yes, go ahead") != "" {
		t.Fatal("the late message reached the model")
	}
	// R4-1: a late halt, even mention-prefixed, is still honoured.
	deliver(target, lateHalt)
	if !e.waitLog(t, 30*time.Second, "accept event="+lateHalt.String()) {
		t.Fatal("FIX REGRESSED (round 6b R4-1): a late halt was dropped")
	}
	waitUntil(t, 30*time.Second, "the halt flag", func() bool {
		data, _ := os.ReadFile(filepath.Join(e.work, "control", "halt.json"))
		return strings.Contains(string(data), `"enabled": true`)
	})
}
