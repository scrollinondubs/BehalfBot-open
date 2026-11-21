package main

import (
	"encoding/json"
	"errors"
	"testing"

	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/id"
)

const testPrincipal = id.UserID("@sean:test.local")

type fakeIdentity struct {
	t   *testing.T
	msk olm.PKSigning
	ssk olm.PKSigning
}

func newKey(t *testing.T) olm.PKSigning {
	t.Helper()
	k, err := olm.NewPKSigning()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newIdentity(t *testing.T) *fakeIdentity {
	return &fakeIdentity{t: t, msk: newKey(t), ssk: newKey(t)}
}

func sign(t *testing.T, obj map[string]any, user id.UserID, keyName string, k olm.PKSigning) {
	t.Helper()
	unsigned := map[string]any{}
	for kk, v := range obj {
		if kk != "signatures" && kk != "unsigned" {
			unsigned[kk] = v
		}
	}
	sig, err := k.SignJSON(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	sigs, _ := obj["signatures"].(map[string]map[string]string)
	if sigs == nil {
		sigs = map[string]map[string]string{}
	}
	if sigs[user.String()] == nil {
		sigs[user.String()] = map[string]string{}
	}
	sigs[user.String()]["ed25519:"+keyName] = sig
	obj["signatures"] = sigs
}

func xsKey(user id.UserID, usage string, k olm.PKSigning) map[string]any {
	pub := k.PublicKey().String()
	return map[string]any{"user_id": user.String(), "usage": []string{usage}, "keys": map[string]string{"ed25519:" + pub: pub}}
}

type fakeDevice struct {
	id       id.DeviceID
	ed       olm.PKSigning
	curve    string
	signedBy olm.PKSigning // nil: not cross-signed
}

func newDevice(t *testing.T, devID string, signedBy olm.PKSigning) fakeDevice {
	return fakeDevice{id: id.DeviceID(devID), ed: newKey(t), curve: newKey(t).PublicKey().String(), signedBy: signedBy}
}

func (fi *fakeIdentity) query(devs ...fakeDevice) []byte {
	t := fi.t
	master := xsKey(testPrincipal, "master", fi.msk)
	self := xsKey(testPrincipal, "self_signing", fi.ssk)
	sign(t, self, testPrincipal, fi.msk.PublicKey().String(), fi.msk)
	devices := map[string]any{}
	for _, d := range devs {
		obj := map[string]any{
			"user_id": testPrincipal.String(), "device_id": d.id.String(),
			"algorithms": []string{"m.olm.v1.curve25519-aes-sha2", "m.megolm.v1.aes-sha2"},
			"keys": map[string]string{
				"ed25519:" + d.id.String():    d.ed.PublicKey().String(),
				"curve25519:" + d.id.String(): d.curve,
			},
		}
		sign(t, obj, testPrincipal, d.id.String(), d.ed)
		if d.signedBy != nil {
			sign(t, obj, testPrincipal, d.signedBy.PublicKey().String(), d.signedBy)
		}
		devices[d.id.String()] = obj
	}
	out, err := json.Marshal(map[string]any{
		"master_keys":       map[string]any{testPrincipal.String(): master},
		"self_signing_keys": map[string]any{testPrincipal.String(): self},
		"device_keys":       map[string]any{testPrincipal.String(): devices},
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestVerifyPrincipalDevice(t *testing.T) {
	sean := newIdentity(t)
	good := newDevice(t, "PHONE", sean.ssk)
	unsigned := newDevice(t, "ROGUE", nil)
	wrongSigner := newDevice(t, "OTHER", newKey(t))
	raw := sean.query(good, unsigned, wrongSigner)
	pin := sean.msk.PublicKey()

	cases := []struct {
		name string
		pin  id.Ed25519
		dev  id.DeviceID
		ed   id.Ed25519
		cv   id.Curve25519
		want error
	}{
		{"cross-signed device", pin, good.id, good.ed.PublicKey(), id.Curve25519(good.curve), nil},
		{"no pin", "", good.id, good.ed.PublicKey(), id.Curve25519(good.curve), ErrNoPin},
		{"different pin (identity changed)", newKey(t).PublicKey(), good.id, good.ed.PublicKey(), id.Curve25519(good.curve), ErrIdentityChanged},
		{"device not cross-signed", pin, unsigned.id, unsigned.ed.PublicKey(), id.Curve25519(unsigned.curve), ErrNotCrossSigned},
		{"device signed by another key", pin, wrongSigner.id, wrongSigner.ed.PublicKey(), id.Curve25519(wrongSigner.curve), ErrNotCrossSigned},
		{"unknown device", pin, "NOPE", good.ed.PublicKey(), id.Curve25519(good.curve), ErrUnknownDevice},
		{"signing key mismatch", pin, good.id, unsigned.ed.PublicKey(), id.Curve25519(good.curve), ErrDeviceKeys},
		{"identity key mismatch", pin, good.id, good.ed.PublicKey(), id.Curve25519(unsigned.curve), ErrDeviceKeys},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := VerifyPrincipalDevice(raw, testPrincipal, c.pin, c.dev, c.ed, c.cv)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}

	devs, err := TrustedPrincipalDevices(raw, testPrincipal, pin)
	if err != nil || len(devs) != 1 || devs[0] != good.id {
		t.Fatalf("trusted devices = %v, %v", devs, err)
	}
	msk, err := PrincipalMasterKey(raw, testPrincipal)
	if err != nil || msk != pin {
		t.Fatalf("master key = %v, %v", msk, err)
	}
}

func TestSelfSigningKeyMustBeSignedByPin(t *testing.T) {
	sean := newIdentity(t)
	good := newDevice(t, "PHONE", sean.ssk)
	raw := sean.query(good)
	var q map[string]map[string]map[string]any
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	// The homeserver swaps in its own self-signing key, signed by a key it
	// controls, and re-signs the device with it.
	forged := newKey(t)
	self := xsKey(testPrincipal, "self_signing", forged)
	sign(t, self, testPrincipal, newKey(t).PublicKey().String(), newKey(t))
	q["self_signing_keys"][testPrincipal.String()] = self
	raw2, _ := json.Marshal(q)
	err := VerifyPrincipalDevice(raw2, testPrincipal, sean.msk.PublicKey(), good.id, good.ed.PublicKey(), id.Curve25519(good.curve))
	if !errors.Is(err, ErrBadSelfSigning) {
		t.Fatalf("got %v, want ErrBadSelfSigning", err)
	}
}

func TestTamperedDeviceKeysFailSignature(t *testing.T) {
	sean := newIdentity(t)
	good := newDevice(t, "PHONE", sean.ssk)
	raw := sean.query(good)
	var q map[string]any
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	dev := q["device_keys"].(map[string]any)[testPrincipal.String()].(map[string]any)["PHONE"].(map[string]any)
	dev["algorithms"] = []string{"m.olm.v1.curve25519-aes-sha2"}
	raw2, _ := json.Marshal(q)
	err := VerifyPrincipalDevice(raw2, testPrincipal, sean.msk.PublicKey(), good.id, good.ed.PublicKey(), id.Curve25519(good.curve))
	if !errors.Is(err, ErrDeviceSelfSig) {
		t.Fatalf("got %v, want ErrDeviceSelfSig", err)
	}
}

func TestFingerprint(t *testing.T) {
	if got := Fingerprint("abcdefghij"); got != "abcd efgh ij" {
		t.Fatal(got)
	}
}
