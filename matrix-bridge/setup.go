package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Prompter is the terminal. Secrets (password, recovery key) are read
// without echo and written only to it: never to argv, env, a log or a file.
type Prompter interface {
	Secret(prompt string) (string, error)
	Line(prompt string) (string, error)
	Say(text string)
}

type ttyPrompter struct {
	f *os.File
	r *bufio.Reader
}

func openTTY() (*ttyPrompter, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("setup must run on an interactive terminal (docker compose run with a TTY)")
	}
	return &ttyPrompter{f: f, r: bufio.NewReader(f)}, nil
}

func (t *ttyPrompter) Secret(prompt string) (string, error) {
	fmt.Fprint(t.f, prompt)
	b, err := term.ReadPassword(int(t.f.Fd()))
	fmt.Fprintln(t.f)
	return strings.TrimSpace(string(b)), err
}

func (t *ttyPrompter) Line(prompt string) (string, error) {
	fmt.Fprint(t.f, prompt)
	s, err := t.r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(s), nil
}

func (t *ttyPrompter) Say(text string) { fmt.Fprintln(t.f, text) }

// Setup logs Jill in (first run), gives her cross-signing keys and a
// self-signed device, joins the chat room, and pins the principal's master
// key after Sean confirms its fingerprint.
func Setup(ctx context.Context, cfg Config, p Prompter) error {
	if err := HardenState(cfg); err != nil {
		return err
	}
	creds, err := LoadCreds(cfg.StateDir)
	var password string
	if err != nil {
		if _, _, err := cfg.JillUser.Parse(); err != nil || cfg.JillUser == "" {
			return errors.New("MATRIX_JILL_USER must be Jill's full Matrix user id (@jill:server)")
		}
		if password, err = p.Secret(fmt.Sprintf("Password for %s: ", cfg.JillUser)); err != nil || password == "" {
			return errors.New("no password entered")
		}
		cli, err := mautrix.NewClient(cfg.Homeserver, "", "")
		if err != nil {
			return err
		}
		resp, err := cli.Login(ctx, &mautrix.ReqLogin{
			Type:                     mautrix.AuthTypePassword,
			Identifier:               mautrix.UserIdentifier{Type: mautrix.IdentifierTypeUser, User: cfg.JillUser.String()},
			Password:                 password,
			InitialDeviceDisplayName: "Jill matrix-bridge",
		})
		if err != nil {
			return fmt.Errorf("login failed: %w", err)
		}
		if resp.UserID != cfg.JillUser {
			return fmt.Errorf("logged in as %s, expected %s", resp.UserID, cfg.JillUser)
		}
		creds = &Creds{Homeserver: cfg.Homeserver, UserID: resp.UserID, DeviceID: resp.DeviceID, AccessToken: resp.AccessToken}
		if err := SaveCreds(cfg.StateDir, creds); err != nil {
			return err
		}
		p.Say(fmt.Sprintf("Logged in as %s, device %s. The access token is in the state volume only.", creds.UserID, creds.DeviceID))
	}

	cli, helper, err := OpenCrypto(ctx, cfg, creds)
	if err != nil {
		return fmt.Errorf("crypto init failed: %w", err)
	}
	defer helper.Close()
	mach := helper.Machine()

	own, err := mach.GetOwnCrossSigningPublicKeys(ctx)
	if err != nil {
		return err
	}
	if own == nil {
		if password == "" {
			if password, err = p.Secret(fmt.Sprintf("Password for %s (to publish cross-signing keys): ", creds.UserID)); err != nil {
				return err
			}
		}
		recovery, _, genErr := mach.GenerateAndUploadCrossSigningKeysWithPassword(ctx, password, "")
		// Shown as soon as it exists, even if a later step fails: the keys
		// may already be on the server, and a re-run needs this key.
		if recovery != "" {
			p.Say("")
			p.Say("JILL'S RECOVERY KEY (shown once, never stored by the bridge; put it in Jill's vault now):")
			p.Say("")
			p.Say("    " + recovery)
			p.Say("")
			if _, err := p.Line("Press Enter once it is saved... "); err != nil {
				return err
			}
		}
		if genErr != nil {
			return fmt.Errorf("could not create cross-signing keys: %w", genErr)
		}
		if err := mach.SignOwnDevice(ctx, mach.OwnIdentity()); err != nil {
			return fmt.Errorf("could not sign Jill's device: %w", err)
		}
		if err := mach.SignOwnMasterKey(ctx); err != nil {
			return fmt.Errorf("could not sign Jill's master key: %w", err)
		}
	} else {
		key, err := p.Secret("Jill already has cross-signing keys. Enter her recovery key to sign with them: ")
		if err != nil || key == "" {
			return errors.New("no recovery key entered")
		}
		if err := mach.VerifyWithRecoveryKey(ctx, key); err != nil {
			return fmt.Errorf("recovery key did not unlock Jill's cross-signing keys: %w", err)
		}
	}
	password = ""

	if _, err := cli.JoinRoomByID(ctx, cfg.Room); err != nil {
		return fmt.Errorf("could not join %s (invite Jill first): %w", cfg.Room, err)
	}
	var enc event.EncryptionEventContent
	if err := cli.StateEvent(ctx, cfg.Room, event.StateEncryption, "", &enc); err != nil || enc.Algorithm != id.AlgorithmMegolmV1 {
		return fmt.Errorf("room %s is not end-to-end encrypted; turn on encryption before setup", cfg.Room)
	}
	// Nothing in this setup may leave a usable room key behind: the room's
	// outbound session is discarded however setup ends (round 6 H1).
	defer func() {
		if err := mach.CryptoStore.RemoveOutboundGroupSession(context.WithoutCancel(ctx), cfg.Room); err != nil {
			p.Say("WARNING: could not discard the setup room key: " + err.Error())
		}
	}()

	b := &Bridge{cfg: cfg, cli: cli}
	// Before anything is encrypted: the room must hold Jill and the
	// principal and nobody else (joined, invited or knocking).
	facts, err := b.roomState(ctx)
	if err != nil {
		return fmt.Errorf("could not read the room's members: %w", err)
	}
	if !exactMembers(facts.members, cli.UserID, cfg.Principal) {
		return fmt.Errorf("the room's members are %v; it must hold exactly %s and %s before setup shares any key",
			facts.members, cli.UserID, cfg.Principal)
	}
	raw, err := b.principalKeys(ctx)
	if err != nil {
		return fmt.Errorf("could not read %s's keys: %w", cfg.Principal, err)
	}
	msk, err := PrincipalMasterKey(raw, cfg.Principal)
	if err != nil {
		return fmt.Errorf("%s has no cross-signing master key; set up encryption in Element X first", cfg.Principal)
	}
	p.Say("")
	p.Say(fmt.Sprintf("Master cross-signing key the server reports for %s (secondary check):", cfg.Principal))
	p.Say("")
	p.Say("    " + Fingerprint(msk))
	p.Say("")
	if cfg.NoSAS {
		p.Say("--no-sas: compare it with the master key your own client shows for your account. Do not")
		p.Say("trust any other copy: this server's admin could forge one.")
		ans, err := p.Line("Type `yes` if it matches exactly: ")
		if err != nil {
			return err
		}
		if ans != "yes" {
			return errors.New("not confirmed; nothing pinned")
		}
		if err := mach.SignUser(ctx, cfg.Principal, msk); err != nil {
			return fmt.Errorf("could not sign the principal's master key: %w", err)
		}
	} else {
		verified, err := verifyPrincipalSAS(ctx, cfg, cli, helper, p)
		if err != nil {
			return fmt.Errorf("verification with %s failed, nothing pinned: %w", cfg.Principal, err)
		}
		if verified != msk {
			return fmt.Errorf("the verified master key differs from the one the server reports now; nothing pinned")
		}
	}
	if err := SavePin(cfg.StateDir, Pin{Principal: cfg.Principal, MasterKey: msk, PinnedAt: nowUnix()}); err != nil {
		return err
	}
	if err := ClearLock(cfg.StateDir); err != nil {
		return err
	}
	ownKeys, _ := mach.GetOwnCrossSigningPublicKeys(ctx)
	p.Say("")
	p.Say("Pinned. Jill's identity, for Element X:")
	p.Say(fmt.Sprintf("  device %s, device key %s", creds.DeviceID, Fingerprint(mach.OwnIdentity().SigningKey)))
	if ownKeys != nil {
		p.Say("  master key " + Fingerprint(ownKeys.MasterKey))
	}
	p.Say("Restart the bridge: docker compose up -d matrix-bridge")
	return nil
}

func exactMembers(members []id.UserID, a, b id.UserID) bool {
	seen := map[id.UserID]bool{}
	for _, m := range members {
		if m != a && m != b {
			return false
		}
		seen[m] = true
	}
	return seen[a] && seen[b]
}
