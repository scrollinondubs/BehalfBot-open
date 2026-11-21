package main

import (
	"errors"

	"maunium.net/go/mautrix/id"
)

const (
	MaxEventAgeMS    = 10 * 60 * 1000
	MaxClockSkewMS   = 60 * 1000
	ReasonAccepted   = ""
	ReasonLocked     = "identity-locked"
	ReasonRoom       = "wrong-room"
	ReasonUnencRoom  = "room-not-encrypted"
	ReasonPlaintext  = "plaintext"
	ReasonUndecrypt  = "undecryptable"
	ReasonMembers    = "extra-members"
	ReasonSender     = "not-principal"
	ReasonForwarded  = "forwarded-keys"
	ReasonNoDevice   = "unknown-sending-device"
	ReasonKeyMatch   = "session-device-mismatch"
	ReasonEdit       = "edit"
	ReasonStale      = "stale"
	ReasonFuture     = "future-timestamp"
	ReasonIdentity   = "identity-changed"
	ReasonNotSigned  = "device-not-cross-signed"
	ReasonCheckError = "trust-check-failed"
	ReasonReplay     = "replay"
	ReasonLate       = "late-delivery"
	ReasonNoIndex    = "megolm-index-unknown"
)

// Inbound is everything the acceptance rule looks at, gathered by the
// caller. The two funcs are lazy because they cost a network round trip
// (DeviceCheck) or claim the event id for good (Claim); they run only when
// every cheaper rule has passed, Claim last.
type Inbound struct {
	IdentityLocked bool

	RoomID        id.RoomID
	ExpectedRoom  id.RoomID
	RoomEncrypted bool
	Members       []id.UserID
	Jill          id.UserID

	WasEncrypted  bool
	Decrypted     bool
	ForwardedKeys bool
	HasDevice     bool
	// SessionMatchesDevice: the Megolm session's sender and signing keys
	// are the device's own (mautrix reports a mismatch, an unknown device,
	// a forwarded or a backed-up key as a distinct trust state).
	SessionMatchesDevice bool

	Sender    id.UserID
	Principal id.UserID

	IsEdit      bool
	TimestampMS int64
	NowMS       int64

	// DeviceCheck verifies the sending device against the pinned master key
	// (VerifyPrincipalDevice). ErrIdentityChanged means the pin no longer
	// matches.
	DeviceCheck func() error
	// IndexKnown is false when the Megolm session and index of the event
	// were not recorded on arrival; Late reports a message older than one
	// already accepted from the same session (round 6b N2).
	IndexKnown bool
	Late       func() bool
	// Claim records the event id as handled and reports whether it was new.
	// Persisted, so a replay across restarts is refused.
	Claim func() (bool, error)
}

// Accept returns "" when the event may be acted on, else a short reason
// for the log. The reason never carries event content.
func Accept(in Inbound) string {
	if in.IdentityLocked {
		return ReasonLocked
	}
	if in.ExpectedRoom == "" || in.RoomID != in.ExpectedRoom {
		return ReasonRoom
	}
	if in.Principal == "" || in.Jill == "" {
		return ReasonSender
	}
	if !in.RoomEncrypted {
		return ReasonUnencRoom
	}
	if !in.WasEncrypted {
		return ReasonPlaintext
	}
	if !in.Decrypted {
		return ReasonUndecrypt
	}
	for _, m := range in.Members {
		if m != in.Jill && m != in.Principal {
			return ReasonMembers
		}
	}
	if in.Principal == "" || in.Sender != in.Principal {
		return ReasonSender
	}
	if in.ForwardedKeys {
		return ReasonForwarded
	}
	if !in.HasDevice {
		return ReasonNoDevice
	}
	if !in.SessionMatchesDevice {
		return ReasonKeyMatch
	}
	if in.IsEdit {
		return ReasonEdit
	}
	if in.NowMS-in.TimestampMS >= MaxEventAgeMS {
		return ReasonStale
	}
	if in.TimestampMS-in.NowMS > MaxClockSkewMS {
		return ReasonFuture
	}
	if in.DeviceCheck == nil {
		return ReasonCheckError
	}
	if err := in.DeviceCheck(); err != nil {
		switch {
		case errors.Is(err, ErrIdentityChanged), errors.Is(err, ErrNoPin):
			return ReasonIdentity
		case errors.Is(err, ErrNotCrossSigned), errors.Is(err, ErrUnknownDevice), errors.Is(err, ErrDeviceKeys),
			errors.Is(err, ErrDeviceSelfSig), errors.Is(err, ErrBadSelfSigning), errors.Is(err, ErrNoMasterKey):
			return ReasonNotSigned
		default:
			return ReasonCheckError
		}
	}
	if !in.IndexKnown {
		return ReasonNoIndex
	}
	if in.Late != nil && in.Late() {
		return ReasonLate
	}
	if in.Claim == nil {
		return ReasonCheckError
	}
	fresh, err := in.Claim()
	if err != nil {
		return ReasonCheckError
	}
	if !fresh {
		return ReasonReplay
	}
	return ReasonAccepted
}

// OutboundCheck is the gate before anything is encrypted and sent. It
// returns "" or a reason; any reason means refuse and alert.
type Outbound struct {
	IdentityLocked bool
	RoomEncrypted  bool
	Members        []id.UserID
	Jill           id.UserID
	Principal      id.UserID
	// TrustedDevices are the principal's devices cross-signed by the pin,
	// from a fresh keys query; error means the pin no longer matches.
	TrustedDevices func() ([]id.DeviceID, error)
}

const (
	OutReasonLocked    = "identity-locked"
	OutReasonUnenc     = "room-not-encrypted"
	OutReasonMembers   = "extra-members"
	OutReasonIdentity  = "identity-changed"
	OutReasonNoDevices = "no-trusted-principal-device"
	OutReasonCheck     = "trust-check-failed"
)

func CheckOutbound(o Outbound) string {
	if o.IdentityLocked {
		return OutReasonLocked
	}
	if !o.RoomEncrypted {
		return OutReasonUnenc
	}
	for _, m := range o.Members {
		if m != o.Jill && m != o.Principal {
			return OutReasonMembers
		}
	}
	if o.TrustedDevices == nil {
		return OutReasonCheck
	}
	devs, err := o.TrustedDevices()
	if err != nil {
		if errors.Is(err, ErrIdentityChanged) || errors.Is(err, ErrNoPin) {
			return OutReasonIdentity
		}
		return OutReasonCheck
	}
	if len(devs) == 0 {
		return OutReasonNoDevices
	}
	return ""
}
