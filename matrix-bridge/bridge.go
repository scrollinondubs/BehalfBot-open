package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
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
	SpoolDir   string
	Worker     []string
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
		SpoolDir:   envOr("ALERT_SPOOL_DIR", "/state/alerts"),
		Worker:     []string{"python3", "-I", envOr("BRIDGE_WORKER", "/app/bridge/matrix_worker.py")},
		MaxAttach:  envInt("BRIDGE_MAX_ATTACHMENT_BYTES", 10_000_000),
		ReadyFile:  envOr("BRIDGE_READY_FILE", "/tmp/bridge-ready"),
	}
	var problems []string
	if _, _, err := c.Principal.Parse(); err != nil || c.Principal == "" {
		problems = append(problems, "MATRIX_PRINCIPAL must be the principal's full Matrix user id (@name:server)")
	}
	if len(c.Room) < 3 || c.Room[0] != '!' {
		problems = append(problems, "MATRIX_JILL_ROOM must be a room id (!id:server), not an alias")
	}
	return c, problems
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
func OpenCrypto(ctx context.Context, cfg Config, creds *Creds) (*mautrix.Client, *cryptohelper.CryptoHelper, error) {
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
	pin     Pin
	locked  atomic.Bool
	chatMu  sync.Mutex
	alerts  *Alerter
	now     func() time.Time
	ready   atomic.Bool
}

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
		Claim: func() (bool, error) { return b.handled.Claim(evt.ID) },
	}
	reason := Accept(in)
	if reason == ReasonIdentity {
		b.lock("the principal's master key differs from the pin")
	}
	if reason != ReasonAccepted {
		logf("drop event=%s reason=%s", evt.ID, reason)
		return
	}
	logf("accept event=%s device=%s", evt.ID, dev.DeviceID)
	go b.handle(context.WithoutCancel(ctx), evt)
}

func (b *Bridge) handle(ctx context.Context, evt *event.Event) {
	content, ok := evt.Content.Parsed.(*event.MessageEventContent)
	if !ok {
		return
	}
	req := WorkerRequest{
		EventID: evt.ID.String(), EventTS: float64(evt.Timestamp) / 1000, Room: b.cfg.Room.String(),
		IsReply: content.RelatesTo != nil && content.RelatesTo.InReplyTo != nil,
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

	resp, err := RunWorker(ctx, b.cfg.Worker, "command", req, 60*time.Second)
	if err != nil {
		logf("WARN: worker command step failed: %v", err)
		b.send(ctx, "The bridge could not process that message (worker error). Nothing was forwarded to the model.")
		return
	}
	if !resp.Handled {
		b.chatMu.Lock()
		resp, err = RunWorker(ctx, b.cfg.Worker, "chat", req, 15*time.Minute)
		b.chatMu.Unlock()
		if err != nil {
			logf("WARN: worker chat step failed: %v", err)
			b.send(ctx, "The bridge could not get a reply (worker error).")
			return
		}
	}
	for _, r := range resp.Replies {
		if !b.send(ctx, r) {
			return
		}
	}
}

// send encrypts text to the principal's pinned-cross-signed devices only,
// after the outbound gate, as plain text (no formatted_body).
func (b *Bridge) send(ctx context.Context, text string) bool {
	facts, err := b.roomState(ctx)
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
			return TrustedPrincipalDevices(raw, b.cfg.Principal, b.pin.MasterKey)
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
			b.lock("the principal's master key differs from the pin")
		case OutReasonMembers, OutReasonUnenc:
			b.alerts.Send("chat-room-changed", "Jill's encrypted chat room changed: it has a member other than Jill and "+
				"Sean, or lost its encryption setting. The bridge refuses to send anything there until that is fixed.")
		}
		return false
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
	cli, helper, err := OpenCrypto(ctx, cfg, creds)
	if err != nil {
		return nil, fmt.Errorf("crypto init failed: %w", err)
	}
	b := &Bridge{cfg: cfg, cli: cli, helper: helper, handled: handled, pin: pin,
		alerts: NewAlerter(cfg.SpoolDir), now: time.Now}
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
