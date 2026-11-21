package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/crypto/verificationhelper"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// SAS (emoji) user verification of the principal, in the encrypted room.
// mautrix's verificationhelper checks the MAC over Sean's device key and
// master key and, on success, signs that master key with Jill's
// user-signing key. Only then is the master key pinned. A homeserver that
// swapped Sean's keys would sit in the middle of the key exchange, and the
// emoji on the two screens would differ.

var sasTimeout = 10 * time.Minute

type sasEvent struct {
	ready   bool
	emojis  []string
	done    bool
	cancel  string
	device  id.DeviceID
	sasOnly bool
}

type sasCallbacks struct {
	txn chan id.VerificationTransactionID
	ev  chan sasEvent
}

func (c *sasCallbacks) VerificationRequested(context.Context, id.VerificationTransactionID, id.UserID, id.DeviceID) {
}

func (c *sasCallbacks) VerificationReady(_ context.Context, _ id.VerificationTransactionID, dev id.DeviceID, supportsSAS, _ bool, _ *verificationhelper.QRCode) {
	c.ev <- sasEvent{ready: true, device: dev, sasOnly: supportsSAS}
}

func (c *sasCallbacks) VerificationCancelled(_ context.Context, _ id.VerificationTransactionID, code event.VerificationCancelCode, reason string) {
	c.ev <- sasEvent{cancel: fmt.Sprintf("%s: %s", code, reason)}
}

func (c *sasCallbacks) VerificationDone(context.Context, id.VerificationTransactionID, event.VerificationMethod) {
	c.ev <- sasEvent{done: true}
}

func (c *sasCallbacks) ShowSAS(_ context.Context, _ id.VerificationTransactionID, emojis []rune, descriptions []string, _ []int) {
	c.ev <- sasEvent{emojis: FormatEmojis(emojis, descriptions)}
}

// FormatEmojis pairs each SAS emoji with its name, as Element shows them.
func FormatEmojis(emojis []rune, descriptions []string) []string {
	out := make([]string, len(emojis))
	for i, r := range emojis {
		d := ""
		if i < len(descriptions) {
			d = descriptions[i]
		}
		out[i] = fmt.Sprintf("%c %s", r, d)
	}
	return out
}

// EmojiConfirmer decides whether the emoji match. Setup asks Sean; the
// integration test compares the two sides.
type EmojiConfirmer func(emojis []string) (bool, error)

func verifyPrincipalSAS(ctx context.Context, cfg Config, cli *mautrix.Client, helper *cryptohelper.CryptoHelper, p Prompter) (id.Ed25519, error) {
	return VerifyUserSAS(ctx, cli, helper, cfg.Room, cfg.Principal, func(emojis []string) (bool, error) {
		p.Say("")
		p.Say("Compare these with the emoji Element X shows for the verification:")
		p.Say("")
		p.Say("    " + strings.Join(emojis, "   "))
		p.Say("")
		ans, err := p.Line("Type `yes` only if they are identical and in the same order (then confirm in Element X too): ")
		return ans == "yes", err
	}, func(msg string) { p.Say(msg) })
}

// VerifyUserSAS runs an in-room SAS verification with `user` and returns
// the master key it verified (and that Jill's user-signing key signed).
func VerifyUserSAS(ctx context.Context, cli *mautrix.Client, helper *cryptohelper.CryptoHelper, room id.RoomID,
	user id.UserID, confirm EmojiConfirmer, say func(string)) (id.Ed25519, error) {
	ctx, cancel := context.WithTimeout(ctx, sasTimeout)
	defer cancel()
	mach := helper.Machine()
	// During verification the request and SAS events must reach Sean's
	// devices that his current master key cross-signs; nothing is pinned
	// yet. A device the server planted is not cross-signed and gets nothing.
	prevMin := mach.SendKeysMinTrust
	mach.SendKeysMinTrust = id.TrustStateCrossSignedTOFU
	defer func() { mach.SendKeysMinTrust = prevMin }()
	prevCrypto := cli.Crypto
	cli.Crypto = OnceCrypto{helper}
	defer func() { cli.Crypto = prevCrypto }()

	cb := &sasCallbacks{ev: make(chan sasEvent, 16)}
	FixInRoomVerificationIDs(cli.Syncer.(mautrix.ExtensibleSyncer), cli.UserID)
	vh := verificationhelper.NewVerificationHelper(cli, mach, nil, cb, false, false, true)
	if err := vh.Init(ctx); err != nil {
		return "", err
	}
	syncCtx, stopSync := context.WithCancel(ctx)
	defer stopSync()
	go func() { _ = cli.SyncWithContext(syncCtx) }()
	defer cli.StopSync()

	// The request is encrypted to the room's members as the state store
	// knows them; load the room state before sending anything.
	if _, err := cli.State(ctx, room); err != nil {
		return "", fmt.Errorf("could not read the room state: %w", err)
	}
	if _, err := mach.FetchKeys(ctx, []id.UserID{user}, true); err != nil {
		return "", fmt.Errorf("could not fetch %s's keys: %w", user, err)
	}
	txn, err := vh.StartInRoomVerification(ctx, room, user)
	if err != nil {
		return "", err
	}
	say(fmt.Sprintf("Verification request sent to %s in the room. Accept it in Element X (it expires in 10 minutes).", user))
	for {
		select {
		case <-ctx.Done():
			return "", errors.New("timed out waiting for the verification")
		case e := <-cb.ev:
			switch {
			case e.cancel != "":
				return "", fmt.Errorf("verification cancelled (%s)", e.cancel)
			case e.ready:
				if !e.sasOnly {
					_ = vh.CancelVerification(ctx, txn, event.VerificationCancelCodeUnknownMethod, "emoji verification required")
					return "", errors.New("the other side does not support emoji (SAS) verification")
				}
				if err := vh.StartSAS(ctx, txn); err != nil {
					// The other side may have started SAS first; that is fine.
					say(fmt.Sprintf("(emoji step not started here: %v)", err))
				}
			case e.emojis != nil:
				ok, err := confirm(e.emojis)
				if err != nil || !ok {
					_ = vh.CancelVerification(ctx, txn, event.VerificationCancelCodeSASMismatch, "emoji did not match")
					return "", errors.New("emoji not confirmed")
				}
				if err := vh.ConfirmSAS(ctx, txn); err != nil {
					return "", err
				}
				say("Confirmed here; waiting for the other side...")
			case e.done:
				trusted, err := mach.IsUserTrusted(ctx, user)
				if err != nil || !trusted {
					return "", errors.New("verification finished but the master key was not signed (was it included in the MAC?)")
				}
				keys, err := mach.GetCrossSigningPublicKeys(ctx, user)
				if err != nil || keys == nil {
					return "", errors.New("verified master key not found")
				}
				return keys.MasterKey, nil
			}
		}
	}
}

// OnceCrypto works around mautrix-go v0.32.0's StartInRoomVerification,
// which encrypts the request itself and then hands it to SendMessageEvent,
// which encrypts it again: the other side decrypts a ciphertext and never
// sees a request. Content that is already encrypted passes through.
type OnceCrypto struct {
	*cryptohelper.CryptoHelper
}

func (o OnceCrypto) Encrypt(ctx context.Context, room id.RoomID, t event.Type, content any) (*event.EncryptedEventContent, error) {
	if enc, ok := content.(*event.EncryptedEventContent); ok {
		return enc, nil
	}
	return o.CryptoHelper.Encrypt(ctx, room, t, content)
}

// FixInRoomVerificationIDs works around a second v0.32.0 (and v0.33.0) bug:
// verificationhelper looks up the transaction of an in-room verification
// event by the event's own id, while the transaction is the id of the
// request it relates to, so every reply to a request is dropped as unknown.
// Registered before the helper, this sets the event id to the relation
// target for those event types; nothing else reads it. Our own echoes keep
// their id, so the helper ignores them as before.
func FixInRoomVerificationIDs(syncer mautrix.ExtensibleSyncer, self id.UserID) {
	fix := func(_ context.Context, evt *event.Event) {
		if evt.Sender == self {
			return
		}
		var c struct {
			RelatesTo struct {
				RelType string     `json:"rel_type"`
				EventID id.EventID `json:"event_id"`
			} `json:"m.relates_to"`
		}
		if json.Unmarshal(evt.Content.VeryRaw, &c) == nil && c.RelatesTo.RelType == string(event.RelReference) && c.RelatesTo.EventID != "" {
			evt.ID = c.RelatesTo.EventID
		}
	}
	for _, t := range []event.Type{event.InRoomVerificationReady, event.InRoomVerificationStart, event.InRoomVerificationDone,
		event.InRoomVerificationCancel, event.InRoomVerificationAccept, event.InRoomVerificationKey, event.InRoomVerificationMAC} {
		syncer.OnEventType(t, fix)
	}
}
