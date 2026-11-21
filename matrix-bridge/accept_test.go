package main

import (
	"errors"
	"os"
	"testing"

	"maunium.net/go/mautrix/id"
)

const (
	testRoom = id.RoomID("!jill:test.local")
	testJill = id.UserID("@jill:test.local")
)

func goodInbound() Inbound {
	return Inbound{
		RoomID: testRoom, ExpectedRoom: testRoom, RoomEncrypted: true,
		Members: []id.UserID{testJill, testPrincipal}, Jill: testJill,
		WasEncrypted: true, Decrypted: true, HasDevice: true, SessionMatchesDevice: true,
		Sender: testPrincipal, Principal: testPrincipal,
		TimestampMS: 1_000_000, NowMS: 1_000_000 + 5_000,
		DeviceCheck: func() error { return nil },
		Claim:       func() (bool, error) { return true, nil },
	}
}

func TestAcceptRules(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*Inbound)
		want string
	}{
		{"accepted", func(*Inbound) {}, ReasonAccepted},
		{"identity locked", func(in *Inbound) { in.IdentityLocked = true }, ReasonLocked},
		{"wrong room", func(in *Inbound) { in.RoomID = "!other:test.local" }, ReasonRoom},
		{"no room configured", func(in *Inbound) { in.ExpectedRoom = ""; in.RoomID = "" }, ReasonRoom},
		{"room lost its encryption state", func(in *Inbound) { in.RoomEncrypted = false }, ReasonUnencRoom},
		{"plaintext event", func(in *Inbound) { in.WasEncrypted = false }, ReasonPlaintext},
		{"undecryptable", func(in *Inbound) { in.Decrypted = false }, ReasonUndecrypt},
		{"extra room member", func(in *Inbound) { in.Members = append(in.Members, "@jax:test.local") }, ReasonMembers},
		{"not the principal", func(in *Inbound) { in.Sender = "@mallory:test.local" }, ReasonSender},
		{"principal unset", func(in *Inbound) { in.Principal = "" }, ReasonSender},
		{"forwarded room key", func(in *Inbound) { in.ForwardedKeys = true }, ReasonForwarded},
		{"sending device unknown", func(in *Inbound) { in.HasDevice = false }, ReasonNoDevice},
		{"session keys are not the device's", func(in *Inbound) { in.SessionMatchesDevice = false }, ReasonKeyMatch},
		{"edit", func(in *Inbound) { in.IsEdit = true }, ReasonEdit},
		{"stale (exactly 10 min)", func(in *Inbound) { in.NowMS = in.TimestampMS + MaxEventAgeMS }, ReasonStale},
		{"stale (an hour)", func(in *Inbound) { in.NowMS = in.TimestampMS + 3_600_000 }, ReasonStale},
		{"future timestamp", func(in *Inbound) { in.TimestampMS = in.NowMS + 2*MaxClockSkewMS }, ReasonFuture},
		{"unpinned MSK (no pin)", func(in *Inbound) { in.DeviceCheck = func() error { return ErrNoPin } }, ReasonIdentity},
		{"MSK differs from pin", func(in *Inbound) { in.DeviceCheck = func() error { return ErrIdentityChanged } }, ReasonIdentity},
		{"device not cross-signed", func(in *Inbound) { in.DeviceCheck = func() error { return ErrNotCrossSigned } }, ReasonNotSigned},
		{"device keys mismatch", func(in *Inbound) { in.DeviceCheck = func() error { return ErrDeviceKeys } }, ReasonNotSigned},
		{"bad self-signing key", func(in *Inbound) { in.DeviceCheck = func() error { return ErrBadSelfSigning } }, ReasonNotSigned},
		{"keys query failed", func(in *Inbound) { in.DeviceCheck = func() error { return errors.New("timeout") } }, ReasonCheckError},
		{"no device check wired", func(in *Inbound) { in.DeviceCheck = nil }, ReasonCheckError},
		{"replay", func(in *Inbound) { in.Claim = func() (bool, error) { return false, nil } }, ReasonReplay},
		{"replay store error", func(in *Inbound) { in.Claim = func() (bool, error) { return false, errors.New("disk") } }, ReasonCheckError},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := goodInbound()
			c.mod(&in)
			if got := Accept(in); got != c.want {
				t.Fatalf("Accept = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRejectedEventsAreNotClaimedOrChecked(t *testing.T) {
	in := goodInbound()
	in.Sender = "@mallory:test.local"
	in.DeviceCheck = func() error { t.Fatal("device check ran for a rejected event"); return nil }
	in.Claim = func() (bool, error) { t.Fatal("claim ran for a rejected event"); return true, nil }
	if Accept(in) != ReasonSender {
		t.Fatal("expected sender rejection")
	}
	in = goodInbound()
	in.DeviceCheck = func() error { return ErrNotCrossSigned }
	in.Claim = func() (bool, error) { t.Fatal("claim ran before the device check passed"); return true, nil }
	Accept(in)
}

func TestReplayAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenHandledStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	in := goodInbound()
	in.Claim = func() (bool, error) { return st.Claim("$evt1") }
	if got := Accept(in); got != ReasonAccepted {
		t.Fatalf("first delivery: %q", got)
	}
	st2, err := OpenHandledStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	in.Claim = func() (bool, error) { return st2.Claim("$evt1") }
	if got := Accept(in); got != ReasonReplay {
		t.Fatalf("replay after restart: %q", got)
	}
}

func TestOutboundGate(t *testing.T) {
	ok := func() ([]id.DeviceID, error) { return []id.DeviceID{"PHONE"}, nil }
	base := Outbound{RoomEncrypted: true, Members: []id.UserID{testJill, testPrincipal}, Jill: testJill, Principal: testPrincipal, TrustedDevices: ok}
	cases := []struct {
		name string
		mod  func(*Outbound)
		want string
	}{
		{"ok", func(*Outbound) {}, ""},
		{"locked", func(o *Outbound) { o.IdentityLocked = true }, OutReasonLocked},
		{"encryption state missing", func(o *Outbound) { o.RoomEncrypted = false }, OutReasonUnenc},
		{"extra member", func(o *Outbound) { o.Members = append(o.Members, "@jax:test.local") }, OutReasonMembers},
		{"identity changed", func(o *Outbound) {
			o.TrustedDevices = func() ([]id.DeviceID, error) { return nil, ErrIdentityChanged }
		}, OutReasonIdentity},
		{"no trusted device", func(o *Outbound) {
			o.TrustedDevices = func() ([]id.DeviceID, error) { return nil, nil }
		}, OutReasonNoDevices},
		{"query error", func(o *Outbound) {
			o.TrustedDevices = func() ([]id.DeviceID, error) { return nil, errors.New("x") }
		}, OutReasonCheck},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := base
			o.Members = append([]id.UserID(nil), base.Members...)
			c.mod(&o)
			if got := CheckOutbound(o); got != c.want {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestExactMembers(t *testing.T) {
	if !exactMembers([]id.UserID{testJill, testPrincipal}, testJill, testPrincipal) {
		t.Fatal("Jill and the principal must pass")
	}
	for _, m := range [][]id.UserID{
		{testJill}, {testPrincipal}, {testJill, testPrincipal, "@eve:test.local"}, {testJill, "@eve:test.local"},
	} {
		if exactMembers(m, testJill, testPrincipal) {
			t.Fatalf("%v must fail", m)
		}
	}
}

func TestRecipientKeyChangesWithMembersDevicesAndPin(t *testing.T) {
	base := recipientKey("PIN", []id.UserID{testJill, testPrincipal}, []id.DeviceID{"A", "B"})
	if base != recipientKey("PIN", []id.UserID{testPrincipal, testJill}, []id.DeviceID{"B", "A"}) {
		t.Fatal("order must not matter")
	}
	for _, other := range []string{
		recipientKey("PIN2", []id.UserID{testJill, testPrincipal}, []id.DeviceID{"A", "B"}),
		recipientKey("PIN", []id.UserID{testJill, testPrincipal, "@eve:test.local"}, []id.DeviceID{"A", "B"}),
		recipientKey("PIN", []id.UserID{testJill, testPrincipal}, []id.DeviceID{"A"}),
	} {
		if other == base {
			t.Fatal("a change of pin, member or device must rotate the session")
		}
	}
}

func TestWorkerUIDProblems(t *testing.T) {
	ok := WorkerSpec{UID: 1000, GID: 1000}
	cases := []struct {
		name   string
		bridge int
		specs  []WorkerSpec
		bad    bool
	}{
		{"root with separate worker and chat uids", 0, []WorkerSpec{ok, {UID: 1001, GID: 1001}}, false},
		{"root, worker uid unset (round 6b N5)", 0, []WorkerSpec{{}}, true},
		{"root, worker uid 0", 0, []WorkerSpec{{UID: 0, GID: 1000}}, true},
		{"root, chat uid unset", 0, []WorkerSpec{ok, {}}, true},
		{"uid without gid", 0, []WorkerSpec{{UID: 1000}}, true},
		{"worker uid equals the bridge uid", 1000, []WorkerSpec{ok}, true},
		{"laptop: non-root, no worker uid", 501, []WorkerSpec{{}, {}}, false},
	}
	for _, c := range cases {
		if got := len(workerUIDProblems(c.bridge, c.specs...)) > 0; got != c.bad {
			t.Errorf("%s: problems=%v, want %v", c.name, got, c.bad)
		}
	}
}

func TestIsHalt(t *testing.T) {
	for _, s := range []string{"halt", "HALT", " halt now", "halt 2h travelling", "mute", "silence!", "Halt."} {
		if !IsHalt(s) {
			t.Errorf("%q should be a halt", s)
		}
	}
	for _, s := range []string{"halting", "should we halt?", "resume", "", "halftime"} {
		if IsHalt(s) {
			t.Errorf("%q should not be a halt", s)
		}
	}
}

func TestPendingHaltSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	b := &Bridge{cfg: Config{StateDir: dir}}
	req := WorkerRequest{EventID: "$h1", Text: "halt", Room: "!r"}
	if err := b.savePendingHalt(req); err != nil {
		t.Fatal(err)
	}
	var p pendingHalt
	if err := readJSON(b.pendingHaltPath("$h1"), &p); err != nil || p.Req.Text != "halt" {
		t.Fatalf("pending halt not persisted: %v %+v", err, p)
	}
	b.clearPendingHalt("$h1")
	if _, err := os.Stat(b.pendingHaltPath("$h1")); !os.IsNotExist(err) {
		t.Fatal("pending halt not cleared")
	}
}
