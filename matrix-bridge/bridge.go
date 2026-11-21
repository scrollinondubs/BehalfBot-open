package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
	_ "modernc.org/sqlite"
)

type Config struct {
	Homeserver string
	Principal  id.UserID
	Room       id.RoomID
	JillUser   id.UserID
	StateDir   string
	Worker     WorkerSpec
	ChatWorker WorkerSpec
	MaxAttach  int64
	ReadyFile  string
	NoSAS      bool
}

func LoadConfig() (Config, []string) {
	c := Config{
		Homeserver: envOr("MATRIX_HOMESERVER", "http://host.docker.internal:8008"),
		Principal:  id.UserID(os.Getenv("MATRIX_PRINCIPAL")),
		Room:       id.RoomID(os.Getenv("MATRIX_JILL_ROOM")),
		JillUser:   id.UserID(os.Getenv("MATRIX_JILL_USER")),
		StateDir:   envOr("MATRIX_BRIDGE_STATE", "/state/matrix-bridge"),
		Worker: WorkerSpec{
			Argv: []string{"python3", "-I", envOr("BRIDGE_WORKER", "/app/bridge/matrix_worker.py")},
			UID:  int(envInt("BRIDGE_WORKER_UID", 0)), GID: int(envInt("BRIDGE_WORKER_GID", 0)),
		},
		// The chat step parses uploaded PDFs and relays model output: it runs
		// as a third uid that can write neither approvals nor the halt and
		// meter flags (round 6b N6). Defaults to the worker uid off-container.
		ChatWorker: WorkerSpec{
			Argv: []string{"python3", "-I", envOr("BRIDGE_WORKER", "/app/bridge/matrix_worker.py")},
			UID:  int(envInt("BRIDGE_CHAT_UID", 0)), GID: int(envInt("BRIDGE_CHAT_GID", 0)),
		},
		MaxAttach: envInt("BRIDGE_MAX_ATTACHMENT_BYTES", 10_000_000),
		ReadyFile: envOr("BRIDGE_READY_FILE", "/tmp/bridge-ready"),
	}
	var problems []string
	if _, _, err := c.Principal.Parse(); err != nil || c.Principal == "" {
		problems = append(problems, "MATRIX_PRINCIPAL must be the principal's full Matrix user id (@name:server)")
	}
	if len(c.Room) < 3 || c.Room[0] != '!' {
		problems = append(problems, "MATRIX_JILL_ROOM must be a room id (!id:server), not an alias")
	}
	problems = append(problems, workerUIDProblems(os.Getuid(), c.Worker, c.ChatWorker)...)
	return c, problems
}

// workerUIDProblems refuses any configuration in which a worker would run
// with the bridge's own uid, and above all as root next to the keys
// (round 6b N5).
func workerUIDProblems(bridgeUID int, worker, chat WorkerSpec) []string {
	var out []string
	// Never fall back: as root, the chat step needs its own uid (round 6b
	// R3-5).
	if bridgeUID == 0 && chat.UID > 0 && chat.UID == worker.UID {
		out = append(out, "BRIDGE_CHAT_UID must differ from BRIDGE_WORKER_UID")
	}
	for _, w := range []WorkerSpec{worker, chat} {
		switch {
		case bridgeUID == 0 && w.UID <= 0:
			out = append(out, "running as root, so BRIDGE_WORKER_UID/GID (and BRIDGE_CHAT_UID/GID) must name a non-root uid and gid for the worker")
		case w.UID > 0 && (w.GID <= 0 || w.UID == bridgeUID):
			out = append(out, "worker uid/gid must be set together and differ from the bridge's own uid")
		}
	}
	return out
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int64) int64 {
	var n int64
	if _, err := fmt.Sscan(os.Getenv(k), &n); err != nil || n <= 0 {
		return def
	}
	return n
}

func logf(format string, args ...any) {
	log.Printf("[matrix-bridge] "+format, args...)
}

// OpenCrypto opens the crypto store in the state volume with a pure-Go
// SQLite driver, so the binary needs neither cgo nor libolm.
// OpenCrypto opens the client and crypto store. Each `pre` handler sees
// m.room.encrypted events before they are decrypted.
func OpenCrypto(ctx context.Context, cfg Config, creds *Creds, pre ...mautrix.EventHandler) (*mautrix.Client, *cryptohelper.CryptoHelper, error) {
	cli, err := mautrix.NewClient(cfg.Homeserver, creds.UserID, creds.AccessToken)
	if err != nil {
		return nil, nil, err
	}
	cli.DeviceID = creds.DeviceID
	level := zerolog.WarnLevel
	if l, err := zerolog.ParseLevel(os.Getenv("MATRIX_BRIDGE_LOG_LEVEL")); err == nil && l != zerolog.NoLevel && l >= zerolog.DebugLevel {
		level = l
	}
	cli.Log = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, NoColor: true}).Level(level).With().Timestamp().
		Str("user", creds.UserID.String()).Logger()
	pickle, err := PickleKey(cfg.StateDir)
	if err != nil {
		return nil, nil, err
	}
	raw, err := sql.Open("sqlite", "file:"+filepath.Join(cfg.StateDir, cryptoDBFile)+
		"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_txlock=immediate")
	if err != nil {
		return nil, nil, err
	}
	raw.SetMaxOpenConns(1)
	db, err := dbutil.NewWithDB(raw, "sqlite3-fk-wal")
	if err != nil {
		return nil, nil, err
	}
	for _, h := range pre {
		cli.Syncer.(*mautrix.DefaultSyncer).OnEventType(event.EventEncrypted, h)
	}
	helper, err := cryptohelper.NewCryptoHelper(cli, pickle, db)
	if err != nil {
		return nil, nil, err
	}
	if err := helper.Init(ctx); err != nil {
		return nil, nil, err
	}
	mach := helper.Machine()
	// Only devices whose master key Jill's user-signing key signed (the
	// pinned one, at setup) get room keys; nobody gets keys on request; no
	// key backup is ever configured.
	mach.SendKeysMinTrust = id.TrustStateCrossSignedVerified
	mach.ShareKeysMinTrust = id.TrustStateCrossSignedVerified
	mach.AllowKeyShare = func(context.Context, *id.Device, event.RequestedKeyInfo) *crypto.KeyShareRejection {
		return &crypto.KeyShareRejectNoResponse
	}
	return cli, helper, nil
}

type Bridge struct {
	cfg     Config
	cli     *mautrix.Client
	helper  *cryptohelper.CryptoHelper
	handled *HandledStore
	index   *IndexStore
	enc     *encRecorder
	pin     Pin
	locked  atomic.Bool
	alerts  *Alerter
	now     func() time.Time
	ready   atomic.Bool

	// Accepted events go through one queue, in the order received, one at a
	// time (round 6 M1); chat that needs the model goes on to a second
	// queue so a model call never delays a `halt`.
	commands chan *event.Event
	chats    chan WorkerRequest

	// The outbound Megolm session is the bridge's own business (round 6
	// H1): discarded at start, rotated whenever the room's members, the
	// principal's pinned-trusted devices or the pin change, and after
	// rotateAfterMessages messages or rotateAfter, whatever the room state
	// says.
	workerMu  sync.Mutex
	sendMu    sync.Mutex
	sessKey   string
	sessCount int
	sessStart time.Time
}

const (
	rotateAfterMessages = 50
	rotateAfter         = 24 * time.Hour
	queueDepth          = 256
)

func (b *Bridge) principalKeys(ctx context.Context) ([]byte, error) {
	body := map[string]any{"device_keys": map[string][]string{b.cfg.Principal.String(): {}}}
	return b.cli.MakeRequest(ctx, "POST", b.cli.BuildClientURL("v3", "keys", "query"), body, nil)
}

type roomFacts struct {
	encrypted bool
	members   []id.UserID
}

// roomState reads the room's state fresh from the server for every
// decision: encryption state and every joined or invited member.
func (b *Bridge) roomState(ctx context.Context) (roomFacts, error) {
	st, err := b.cli.State(ctx, b.cfg.Room)
	if err != nil {
		return roomFacts{}, err
	}
	var f roomFacts
	if enc, ok := st[event.StateEncryption][""]; ok && enc != nil {
		if c, ok := enc.Content.Parsed.(*event.EncryptionEventContent); ok && c.Algorithm == id.AlgorithmMegolmV1 {
			f.encrypted = true
		}
	}
	for key, evt := range st[event.StateMember] {
		if evt == nil {
			continue
		}
		c, ok := evt.Content.Parsed.(*event.MemberEventContent)
		if !ok {
			continue
		}
		switch c.Membership {
		case event.MembershipJoin, event.MembershipInvite, event.MembershipKnock:
			f.members = append(f.members, id.UserID(key))
		}
	}
	return f, nil
}

func (b *Bridge) lock(reason string) {
	if b.locked.Swap(true) {
		return
	}
	if err := SaveLock(b.cfg.StateDir, reason); err != nil {
		logf("ERROR: could not persist the identity lock: %v", err)
	}
	logf("IDENTITY LOCK: %s. Chat and commands are refused until `matrix-bridge setup` re-pins.", reason)
	b.discardSession(context.Background())
	b.alerts.Send("chat-identity", "Jill's encrypted chat bridge stopped accepting messages: Sean's Matrix cross-signing "+
		"identity no longer matches the one pinned at setup. Chat and commands are refused until setup is re-run "+
		"on Jill's machine. If you did not reset your Matrix identity, treat this as an attack.")
}

func isEdit(raw json.RawMessage) bool {
	var c struct {
		NewContent json.RawMessage `json:"m.new_content"`
		RelatesTo  *struct {
			RelType string `json:"rel_type"`
		} `json:"m.relates_to"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return true
	}
	return len(c.NewContent) > 0 || (c.RelatesTo != nil && c.RelatesTo.RelType == string(event.RelReplace))
}

// sessionMatchesDevice is false for the trust states mautrix assigns when
// the room key did not come straight from the device that owns it. The
// positive trust decision is VerifyPrincipalDevice, never this.
func sessionMatchesDevice(ts id.TrustState) bool {
	switch ts {
	case id.TrustStateDeviceKeyMismatch, id.TrustStateUnknownDevice, id.TrustStateForwarded,
		id.TrustStateBackup, id.TrustStateBlacklisted, id.TrustStateInvalid:
		return false
	}
	return true
}

func (b *Bridge) onPlaintext(ctx context.Context, evt *event.Event) {
	if evt.RoomID != b.cfg.Room || evt.Mautrix.WasEncrypted {
		return
	}
	logf("drop event=%s reason=%s", evt.ID, ReasonPlaintext)
}

func (b *Bridge) onDecryptError(evt *event.Event, err error) {
	if evt.RoomID != b.cfg.Room {
		return
	}
	logf("drop event=%s reason=%s", evt.ID, ReasonUndecrypt)
}

func (b *Bridge) onDecrypted(ctx context.Context, evt *event.Event) {
	if evt.Sender == b.cli.UserID {
		return
	}
	if evt.RoomID != b.cfg.Room {
		logf("drop event=%s reason=%s", evt.ID, ReasonRoom)
		return
	}
	if evt.Type != event.EventMessage {
		return
	}
	facts, err := b.roomState(ctx)
	if err != nil {
		logf("drop event=%s reason=%s", evt.ID, ReasonCheckError)
		return
	}
	dev := evt.Mautrix.TrustSource
	ref, refOK := b.enc.Take(evt.ID)
	var key string
	if refOK && dev != nil {
		key = indexKey(dev.IdentityKey, ref.session)
	}
	content, _ := evt.Content.Parsed.(*event.MessageEventContent)
	// A halt is written to disk before its event id is claimed (round 6b
	// R3-6): a crash between the two cannot lose it.
	var haltReq *WorkerRequest
	if content != nil && content.MsgType == event.MsgText && IsHalt(content.Body) {
		haltReq = &WorkerRequest{EventID: evt.ID.String(), Room: b.cfg.Room.String(), Text: content.Body,
			ReceivedAt: float64(time.Now().UnixNano()) / 1e9}
		if err := b.savePendingHalt(*haltReq); err != nil {
			logf("ERROR: could not persist halt %s: %v", evt.ID, err)
		}
	}
	in := Inbound{
		IdentityLocked: b.locked.Load(),
		RoomID:         evt.RoomID, ExpectedRoom: b.cfg.Room,
		RoomEncrypted: facts.encrypted, Members: facts.members, Jill: b.cli.UserID,
		WasEncrypted: evt.Mautrix.WasEncrypted, Decrypted: evt.Mautrix.EventSource&event.SourceDecrypted != 0,
		ForwardedKeys: evt.Mautrix.ForwardedKeys, HasDevice: dev != nil,
		SessionMatchesDevice: sessionMatchesDevice(evt.Mautrix.TrustState),
		Sender:               evt.Sender, Principal: b.cfg.Principal,
		IsEdit:      isEdit(evt.Content.VeryRaw),
		TimestampMS: evt.Timestamp, NowMS: b.now().UnixMilli(),
		DeviceCheck: func() error {
			raw, err := b.principalKeys(ctx)
			if err != nil {
				return err
			}
			return VerifyPrincipalDevice(raw, b.cfg.Principal, b.pin.MasterKey, dev.DeviceID, dev.SigningKey, dev.IdentityKey)
		},
		IndexKnown: refOK && dev != nil,
		IsHalt:     haltReq != nil,
		Late:       func() bool { return b.index.Late(key, ref.index) },
		Claim:      func() (bool, error) { return b.handled.Claim(evt.ID) },
	}
	reason := Accept(in)
	if reason == ReasonIdentity {
		b.lock("the principal's master key differs from the pin")
	}
	if reason != ReasonAccepted {
		logf("drop event=%s reason=%s", evt.ID, reason)
		if haltReq != nil {
			b.clearPendingHalt(haltReq.EventID)
		}
		if reason == ReasonLate {
			go b.send(context.WithoutCancel(ctx), "[bridge] An older message arrived late and was not sent to Jill: \""+
				preview(content, 40)+"\". If you still mean it, send it again.")
		}
		return
	}
	if err := b.index.Accept(key, ref.index); err != nil {
		logf("ERROR: could not persist the Megolm index: %v", err)
	}
	logf("accept event=%s device=%s", evt.ID, dev.DeviceID)
	if haltReq != nil {
		// A halt skips the queue and its length limit (round 6b N8).
		b.process(context.WithoutCancel(ctx), *haltReq)
		b.clearPendingHalt(haltReq.EventID)
		return
	}
	select {
	case b.commands <- evt:
	default:
		logf("drop event=%s reason=queue-full", evt.ID)
		go b.send(context.WithoutCancel(ctx), "[bridge] Too many messages are waiting; that one was dropped. A `halt` always gets through.")
	}
}

// A leading mention is allowed, as the worker's parser allows it (round 6b
// R3-6).
// preview is the first n characters of a message, on one line, with control
// characters removed, for a bridge notice.
func preview(c *event.MessageEventContent, n int) string {
	if c == nil {
		return "(no text)"
	}
	body := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == '"' {
			return ' '
		}
		return r
	}, c.Body)
	if r := []rune(body); len(r) > n {
		body = string(r[:n]) + "..."
	}
	return body
}

var haltRE = regexp.MustCompile(`(?i)^\s*(@[^:\s]+:[A-Za-z0-9.\-\[\]]+(:\d+)?:?\s*)?[!.?,;:]*\s*(halt|mute|silence)(\s|[!.?,;:]|$)`)

// IsHalt matches the halt words the worker's parser accepts.
func IsHalt(body string) bool { return haltRE.MatchString(body) }

type pendingHalt struct {
	Req WorkerRequest `json:"req"`
}

func (b *Bridge) pendingHaltPath(eventID string) string {
	sum := sha256.Sum256([]byte(eventID))
	return filepath.Join(b.cfg.StateDir, "pending-halt-"+hex.EncodeToString(sum[:8])+".json")
}

func (b *Bridge) savePendingHalt(req WorkerRequest) error {
	return writeJSON0600(b.pendingHaltPath(req.EventID), pendingHalt{Req: req})
}

func (b *Bridge) clearPendingHalt(eventID string) {
	if err := os.Remove(b.pendingHaltPath(eventID)); err != nil && !errors.Is(err, os.ErrNotExist) {
		logf("WARN: could not clear pending halt: %v", err)
	}
}

// replayPendingHalts applies halts that were accepted but not finished
// before a restart.
func (b *Bridge) replayPendingHalts(ctx context.Context) {
	matches, _ := filepath.Glob(filepath.Join(b.cfg.StateDir, "pending-halt-*.json"))
	for _, m := range matches {
		var p pendingHalt
		if err := readJSON(m, &p); err != nil || !IsHalt(p.Req.Text) {
			logf("WARN: unreadable pending halt %s; applying a plain halt", filepath.Base(m))
			p.Req = WorkerRequest{Room: b.cfg.Room.String(), Text: "halt", ReceivedAt: float64(time.Now().Unix())}
		}
		logf("applying a halt accepted before the restart (event %s)", p.Req.EventID)
		b.process(ctx, p.Req)
		_ = os.Remove(m)
	}
}

// commandLoop handles accepted events one at a time, in the order they were
// accepted: a `halt` is never overtaken by an earlier `confirm`, and the
// worker's code store is never written by two processes at once.
func (b *Bridge) commandLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt := <-b.commands:
			b.handle(context.WithoutCancel(ctx), evt)
		}
	}
}

func (b *Bridge) chatLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-b.chats:
			resp, err := RunWorker(context.WithoutCancel(ctx), b.cfg.ChatWorker, "chat", req, 15*time.Minute)
			if err != nil {
				logf("WARN: worker chat step failed: %v", err)
				b.send(ctx, "[bridge] The bridge could not get a reply (worker error).")
				continue
			}
			b.deliver(ctx, resp)
		}
	}
}

// deliver sends every reply, then activates the one-time codes they carry:
// a code on a message that did not go out is never usable.
func (b *Bridge) deliver(ctx context.Context, resp *WorkerResponse) {
	for _, r := range resp.Replies {
		if !b.send(ctx, r) {
			return
		}
	}
	if len(resp.Activate) > 0 {
		if _, err := RunWorker(ctx, b.cfg.Worker, "activate", WorkerRequest{Activate: resp.Activate}, 30*time.Second); err != nil {
			logf("WARN: could not activate codes: %v", err)
		}
	}
}

func (b *Bridge) handle(ctx context.Context, evt *event.Event) {
	content, ok := evt.Content.Parsed.(*event.MessageEventContent)
	if !ok {
		return
	}
	req := WorkerRequest{
		EventID: evt.ID.String(), EventTS: float64(evt.Timestamp) / 1000, Room: b.cfg.Room.String(),
		ReceivedAt: float64(time.Now().UnixNano()) / 1e9,
	}
	switch content.MsgType {
	case event.MsgText:
		req.Text = content.Body
	case event.MsgFile:
		if content.FileName != "" && content.Body != content.FileName {
			req.Text = content.Body
		}
		att, note := b.fetchAttachment(ctx, content)
		if att != nil {
			req.Attachments = append(req.Attachments, *att)
		}
		if note != "" {
			req.Notes = append(req.Notes, note)
		}
	default:
		name := content.FileName
		if name == "" {
			name = string(content.MsgType)
		}
		req.Notes = append(req.Notes, fmt.Sprintf("(skipped %s: unsupported message type)", name))
		req.Unsupported = true
	}
	b.process(ctx, req)
}

// process runs the command step for one message. Command steps never
// overlap (the halt fast path and the queue share this lock), so the
// worker's code store has one writer at a time.
func (b *Bridge) process(ctx context.Context, req WorkerRequest) {
	b.workerMu.Lock()
	defer b.workerMu.Unlock()
	resp, err := RunWorker(ctx, b.cfg.Worker, "command", req, 60*time.Second)
	if err != nil {
		logf("WARN: worker command step failed: %v", err)
		b.send(ctx, "[bridge] The bridge could not process that message (worker error). Nothing was forwarded to the model.")
		return
	}
	if !resp.Handled {
		select {
		case b.chats <- req:
		default:
			b.send(ctx, "[bridge] Too many messages are waiting for the model; that one was dropped.")
		}
		return
	}
	b.deliver(ctx, resp)
}

func (b *Bridge) discardSession(ctx context.Context) {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	b.discardSessionLocked(ctx)
}

func (b *Bridge) discardSessionLocked(ctx context.Context) {
	if err := b.helper.Machine().CryptoStore.RemoveOutboundGroupSession(ctx, b.cfg.Room); err != nil {
		logf("WARN: could not discard the outbound room key: %v", err)
	}
	b.sessKey, b.sessCount = "", 0
}

// recipientKey changes whenever who may hold the room key changes.
func recipientKey(pin id.Ed25519, members []id.UserID, devices []id.DeviceID) string {
	m := append([]id.UserID(nil), members...)
	slices.Sort(m)
	d := append([]id.DeviceID(nil), devices...)
	slices.Sort(d)
	return fmt.Sprintf("%s|%v|%v", pin, m, d)
}

// send encrypts text to the principal's pinned-cross-signed devices only,
// after the outbound gate, as plain text (no formatted_body).
func (b *Bridge) send(ctx context.Context, text string) bool {
	b.sendMu.Lock()
	defer b.sendMu.Unlock()
	facts, err := b.roomState(ctx)
	var trusted []id.DeviceID
	o := Outbound{
		IdentityLocked: b.locked.Load(),
		RoomEncrypted:  err == nil && facts.encrypted,
		Members:        facts.members,
		Jill:           b.cli.UserID, Principal: b.cfg.Principal,
		TrustedDevices: func() ([]id.DeviceID, error) {
			raw, err := b.principalKeys(ctx)
			if err != nil {
				return nil, err
			}
			trusted, err = TrustedPrincipalDevices(raw, b.cfg.Principal, b.pin.MasterKey)
			return trusted, err
		},
	}
	if err != nil {
		logf("refuse send reason=%s", OutReasonCheck)
		return false
	}
	if reason := CheckOutbound(o); reason != "" {
		logf("refuse send reason=%s", reason)
		switch reason {
		case OutReasonIdentity:
			b.sendMu.Unlock()
			b.lock("the principal's master key differs from the pin")
			b.sendMu.Lock()
		case OutReasonMembers, OutReasonUnenc:
			b.alerts.Send("chat-room-changed", "Jill's encrypted chat room changed: it has a member other than Jill and "+
				"Sean, or lost its encryption setting. The bridge refuses to send anything there until that is fixed.")
		}
		return false
	}
	key := recipientKey(b.pin.MasterKey, facts.members, trusted)
	if key != b.sessKey || b.sessCount >= rotateAfterMessages || time.Since(b.sessStart) > rotateAfter {
		b.discardSessionLocked(ctx)
		b.sessKey, b.sessStart = key, time.Now()
	}
	mach := b.helper.Machine()
	if err := mach.ShareGroupSession(ctx, b.cfg.Room, []id.UserID{b.cfg.Principal, b.cli.UserID}); err != nil {
		logf("WARN: could not share the room key: %v", err)
		return false
	}
	msg := &event.MessageEventContent{MsgType: event.MsgText, Body: text}
	enc, err := mach.EncryptMegolmEvent(ctx, b.cfg.Room, event.EventMessage, msg)
	if errors.Is(err, crypto.ErrNoGroupSession) {
		if err = mach.ShareGroupSession(ctx, b.cfg.Room, []id.UserID{b.cfg.Principal, b.cli.UserID}); err == nil {
			enc, err = mach.EncryptMegolmEvent(ctx, b.cfg.Room, event.EventMessage, msg)
		}
	}
	if err != nil {
		logf("WARN: encrypt failed: %v", err)
		return false
	}
	if _, err := b.cli.SendMessageEvent(ctx, b.cfg.Room, event.EventEncrypted, enc); err != nil {
		logf("WARN: send failed: %v", err)
		return false
	}
	b.sessCount++
	return true
}

func (b *Bridge) fetchAttachment(ctx context.Context, c *event.MessageEventContent) (*WorkerAttachment, string) {
	name := c.FileName
	if name == "" {
		name = c.Body
	}
	mime := ""
	var size int
	if c.Info != nil {
		mime, size = c.Info.MimeType, c.Info.Size
	}
	if c.File == nil {
		// An unencrypted upload is readable and replaceable by the
		// homeserver; only encrypted media (with its hash) is accepted.
		return nil, fmt.Sprintf("(skipped attachment %s: not end-to-end encrypted)", name)
	}
	if int64(size) > b.cfg.MaxAttach {
		return nil, fmt.Sprintf("(skipped attachment %s: %d bytes is over the %d byte limit)", name, size, b.cfg.MaxAttach)
	}
	uri, err := c.File.URL.Parse()
	if err != nil {
		return nil, fmt.Sprintf("(skipped attachment %s: bad media url)", name)
	}
	resp, err := b.cli.DownloadWithParams(ctx, uri, mautrix.DownloadExtra{})
	if err != nil {
		return nil, fmt.Sprintf("(skipped attachment %s: download failed)", name)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, b.cfg.MaxAttach+1))
	if err != nil {
		return nil, fmt.Sprintf("(skipped attachment %s: download failed)", name)
	}
	if int64(len(data)) > b.cfg.MaxAttach {
		return nil, fmt.Sprintf("(skipped attachment %s: over the %d byte limit)", name, b.cfg.MaxAttach)
	}
	if err := c.File.DecryptInPlace(data); err != nil {
		return nil, fmt.Sprintf("(skipped attachment %s: decryption or hash check failed)", name)
	}
	return &WorkerAttachment{Name: name, Mime: mime, Size: len(data), Data: data}, ""
}

func Run(ctx context.Context, cfg Config) error {
	b, err := NewBridge(ctx, cfg)
	if err != nil {
		return err
	}
	defer b.helper.Close()
	return b.cli.SyncWithContext(ctx)
}

// NewBridge loads the login, pin and stores and wires the handlers; the
// caller runs the sync.
func NewBridge(ctx context.Context, cfg Config) (*Bridge, error) {
	if err := HardenState(cfg); err != nil {
		return nil, err
	}
	creds, err := LoadCreds(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("no usable login in %s (%v): run `matrix-bridge setup` first", cfg.StateDir, err)
	}
	if cfg.Homeserver == "" {
		cfg.Homeserver = creds.Homeserver
	}
	pin, err := LoadPin(cfg.StateDir, cfg.Principal)
	if err != nil {
		return nil, err
	}
	handled, err := OpenHandledStore(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	index, err := OpenIndexStore(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	enc := newEncRecorder()
	cli, helper, err := OpenCrypto(ctx, cfg, creds, enc.Record)
	if err != nil {
		return nil, fmt.Errorf("crypto init failed: %w", err)
	}
	b := &Bridge{cfg: cfg, cli: cli, helper: helper, handled: handled, index: index, enc: enc, pin: pin,
		alerts: NewAlerter(cfg.Worker), now: time.Now,
		commands: make(chan *event.Event, queueDepth), chats: make(chan WorkerRequest, queueDepth)}
	// Whatever session is in the store was created under an earlier state
	// of the room or the pin (setup included): never reuse it (round 6 H1).
	b.discardSession(ctx)
	b.replayPendingHalts(ctx)
	go b.commandLoop(ctx)
	go b.chatLoop(ctx)
	if l, _ := LoadLock(cfg.StateDir); l != nil {
		b.locked.Store(true)
		logf("IDENTITY LOCK is set (%s): refusing chat and commands until setup re-pins", l.Reason)
	}
	if pin.MasterKey == "" {
		b.lock("no principal master key is pinned (setup has not completed)")
	} else if raw, err := b.principalKeys(ctx); err != nil {
		logf("WARN: could not read the principal's keys at boot: %v", err)
	} else if msk, err := PrincipalMasterKey(raw, cfg.Principal); err != nil || msk != pin.MasterKey {
		b.lock("the principal's master key differs from the pin")
	}
	if hasKeys, verified, err := helper.Machine().GetOwnVerificationStatus(ctx); err != nil || !hasKeys || !verified {
		logf("WARN: Jill's own device is not cross-signed (keys=%v verified=%v); Element X will not encrypt to it. Run setup.", hasKeys, verified)
	}

	syncer := cli.Syncer.(*mautrix.DefaultSyncer)
	helper.CustomPostDecrypt = b.onDecrypted
	helper.DecryptErrorCallback = b.onDecryptError
	syncer.OnEventType(event.EventMessage, b.onPlaintext)
	syncer.OnSync(func(ctx context.Context, resp *mautrix.RespSync, since string) bool {
		if !b.ready.Swap(true) && cfg.ReadyFile != "" {
			_ = os.WriteFile(cfg.ReadyFile, []byte("synced\n"), 0o644)
			logf("first sync done; listening in %s for %s (pinned master key %s)", cfg.Room, cfg.Principal, Fingerprint(pin.MasterKey))
		}
		return true
	})
	return b, nil
}
