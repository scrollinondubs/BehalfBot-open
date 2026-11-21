package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"maunium.net/go/mautrix/crypto/signatures"
	"maunium.net/go/mautrix/id"
)

// The trust decision is made here, from the raw /keys/query JSON, against
// the principal master key pinned at setup. mautrix's own TrustState is not
// used for it: its TOFU level is relative to the first master key the store
// ever saw, and the homeserver supplied that.

var (
	ErrNoPin           = errors.New("no pinned principal master key")
	ErrIdentityChanged = errors.New("principal master key differs from the pin")
	ErrNoMasterKey     = errors.New("principal has no master key")
	ErrBadSelfSigning  = errors.New("principal self-signing key is missing or not signed by the pinned master key")
	ErrUnknownDevice   = errors.New("device is not in the principal's device list")
	ErrDeviceKeys      = errors.New("device keys do not match the keys that encrypted the event")
	ErrDeviceSelfSig   = errors.New("device keys are not signed by the device itself")
	ErrNotCrossSigned  = errors.New("device is not cross-signed by the pinned master key")
)

type rawKeysQuery struct {
	DeviceKeys      map[id.UserID]map[id.DeviceID]json.RawMessage `json:"device_keys"`
	MasterKeys      map[id.UserID]json.RawMessage                 `json:"master_keys"`
	SelfSigningKeys map[id.UserID]json.RawMessage                 `json:"self_signing_keys"`
}

type crossSigningKey struct {
	UserID id.UserID         `json:"user_id"`
	Usage  []string          `json:"usage"`
	Keys   map[string]string `json:"keys"`
}

type deviceKeys struct {
	UserID   id.UserID         `json:"user_id"`
	DeviceID id.DeviceID       `json:"device_id"`
	Keys     map[string]string `json:"keys"`
}

func parseKeysQuery(raw []byte) (*rawKeysQuery, error) {
	var q rawKeysQuery
	if err := json.Unmarshal(raw, &q); err != nil {
		return nil, fmt.Errorf("keys query is not valid JSON: %w", err)
	}
	return &q, nil
}

// singleKey returns the only ed25519 key of a cross-signing key object whose
// user and usage are as expected.
func singleKey(raw json.RawMessage, user id.UserID, usage string) (id.Ed25519, error) {
	if len(raw) == 0 {
		return "", errors.New("missing")
	}
	var k crossSigningKey
	if err := json.Unmarshal(raw, &k); err != nil {
		return "", err
	}
	if k.UserID != user || !slices.Contains(k.Usage, usage) || len(k.Keys) != 1 {
		return "", errors.New("malformed")
	}
	for keyID, key := range k.Keys {
		if keyID != "ed25519:"+key || len(key) != 43 {
			return "", errors.New("malformed key id")
		}
		return id.Ed25519(key), nil
	}
	return "", errors.New("missing")
}

// PrincipalMasterKey is the principal's current master key as the server
// reports it. It proves nothing on its own; compare it with the pin.
func PrincipalMasterKey(raw []byte, principal id.UserID) (id.Ed25519, error) {
	q, err := parseKeysQuery(raw)
	if err != nil {
		return "", err
	}
	msk, err := singleKey(q.MasterKeys[principal], principal, "master")
	if err != nil {
		return "", ErrNoMasterKey
	}
	return msk, nil
}

// pinnedSelfSigningKey checks master == pin and returns the self-signing key
// the pinned master key has signed.
func pinnedSelfSigningKey(q *rawKeysQuery, principal id.UserID, pin id.Ed25519) (id.Ed25519, error) {
	if pin == "" {
		return "", ErrNoPin
	}
	msk, err := singleKey(q.MasterKeys[principal], principal, "master")
	if err != nil {
		return "", ErrNoMasterKey
	}
	if msk != pin {
		return "", ErrIdentityChanged
	}
	rawSSK := q.SelfSigningKeys[principal]
	ssk, err := singleKey(rawSSK, principal, "self_signing")
	if err != nil {
		return "", ErrBadSelfSigning
	}
	if ok, _ := signatures.VerifySignatureJSON(json.RawMessage(rawSSK), principal, pin.String(), pin); !ok {
		return "", ErrBadSelfSigning
	}
	return ssk, nil
}

// VerifyPrincipalDevice proves that deviceID belongs to the principal, has
// exactly the keys the event was encrypted with, and is signed by the
// self-signing key that the PINNED master key signed.
func VerifyPrincipalDevice(raw []byte, principal id.UserID, pin id.Ed25519, deviceID id.DeviceID,
	signingKey id.Ed25519, identityKey id.Curve25519) error {
	q, err := parseKeysQuery(raw)
	if err != nil {
		return err
	}
	ssk, err := pinnedSelfSigningKey(q, principal, pin)
	if err != nil {
		return err
	}
	return verifyDevice(q.DeviceKeys[principal][deviceID], principal, deviceID, ssk, signingKey, identityKey)
}

func verifyDevice(rawDev json.RawMessage, principal id.UserID, deviceID id.DeviceID, ssk id.Ed25519,
	signingKey id.Ed25519, identityKey id.Curve25519) error {
	if len(rawDev) == 0 {
		return ErrUnknownDevice
	}
	var dev deviceKeys
	if err := json.Unmarshal(rawDev, &dev); err != nil {
		return ErrUnknownDevice
	}
	if dev.UserID != principal || dev.DeviceID != deviceID {
		return ErrUnknownDevice
	}
	ed := dev.Keys["ed25519:"+deviceID.String()]
	curve := dev.Keys["curve25519:"+deviceID.String()]
	if ed == "" || ed != signingKey.String() || (identityKey != "" && curve != identityKey.String()) {
		return ErrDeviceKeys
	}
	if ok, _ := signatures.VerifySignatureJSON(rawDev, principal, deviceID.String(), id.Ed25519(ed)); !ok {
		return ErrDeviceSelfSig
	}
	if ok, _ := signatures.VerifySignatureJSON(rawDev, principal, ssk.String(), ssk); !ok {
		return ErrNotCrossSigned
	}
	return nil
}

// TrustedPrincipalDevices lists the principal's devices cross-signed by the
// pinned master key. The outbound gate uses it to refuse sending when the
// principal has no device that could read the reply.
func TrustedPrincipalDevices(raw []byte, principal id.UserID, pin id.Ed25519) ([]id.DeviceID, error) {
	q, err := parseKeysQuery(raw)
	if err != nil {
		return nil, err
	}
	ssk, err := pinnedSelfSigningKey(q, principal, pin)
	if err != nil {
		return nil, err
	}
	var out []id.DeviceID
	for devID, rawDev := range q.DeviceKeys[principal] {
		var dev deviceKeys
		if json.Unmarshal(rawDev, &dev) != nil {
			continue
		}
		ed := id.Ed25519(dev.Keys["ed25519:"+devID.String()])
		if verifyDevice(rawDev, principal, devID, ssk, ed, "") == nil {
			out = append(out, devID)
		}
	}
	slices.Sort(out)
	return out, nil
}

// Fingerprint formats an ed25519 key the way Element shows keys: groups of
// four characters.
func Fingerprint(key id.Ed25519) string {
	s := key.String()
	out := make([]byte, 0, len(s)+len(s)/4)
	for i := 0; i < len(s); i++ {
		if i > 0 && i%4 == 0 {
			out = append(out, ' ')
		}
		out = append(out, s[i])
	}
	return string(out)
}
