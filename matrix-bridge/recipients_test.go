package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/id"
)

// Who receives room keys is decided by mautrix (findOlmSessionsForUser:
// trust < SendKeysMinTrust is withheld). This checks that the settings
// OpenCrypto applies bind that decision to the pinned master key, with the
// store in the state it is in after a restart: Jill's cross-signing private
// keys are not loaded, only the public keys and the signatures setup
// stored. mautrix stores a signature only after verifying it, so the
// strings here stand in for verified signatures, as in mautrix's own tests.
func TestRoomKeysGoOnlyToDevicesUnderThePinnedMasterKey(t *testing.T) {
	ctx := context.Background()
	raw, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "c.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	raw.SetMaxOpenConns(1)
	db, err := dbutil.NewWithDB(raw, "sqlite3-fk-wal")
	if err != nil {
		t.Fatal(err)
	}
	store := crypto.NewSQLCryptoStore(db, dbutil.NoopLogger, "", "JILLDEV", []byte("pickle"))
	if err := store.DB.Upgrade(ctx); err != nil {
		t.Fatal(err)
	}
	log := zerolog.Nop()
	cli := &mautrix.Client{UserID: testJill, DeviceID: "JILLDEV", Log: log}
	mach := crypto.NewOlmMachine(cli, &log, store, mautrix.NewMemoryStateStore().(crypto.StateStore))
	if err := mach.Load(ctx); err != nil {
		t.Fatal(err)
	}
	mach.SendKeysMinTrust = id.TrustStateCrossSignedVerified
	mach.CrossSigningKeys = nil

	put := func(user id.UserID, usage id.CrossSigningUsage, k id.Ed25519) {
		if err := store.PutCrossSigningKey(ctx, user, usage, k); err != nil {
			t.Fatal(err)
		}
	}
	sig := func(user id.UserID, key id.Ed25519, signer id.UserID, signerKey id.Ed25519) {
		if err := store.PutSignature(ctx, user, key, signer, signerKey, "verified"); err != nil {
			t.Fatal(err)
		}
	}

	// Jill, as setup leaves her: MSK signed by her device, SSK/USK by MSK.
	jMSK, jSSK, jUSK := newKey(t).PublicKey(), newKey(t).PublicKey(), newKey(t).PublicKey()
	put(testJill, id.XSUsageMaster, jMSK)
	put(testJill, id.XSUsageSelfSigning, jSSK)
	put(testJill, id.XSUsageUserSigning, jUSK)
	sig(testJill, jMSK, testJill, mach.GetAccount().SigningKey())
	sig(testJill, jSSK, testJill, jMSK)
	sig(testJill, jUSK, testJill, jMSK)

	// Sean: the pinned MSK, signed by Jill's USK at setup.
	sMSK, sSSK := newKey(t).PublicKey(), newKey(t).PublicKey()
	put(testPrincipal, id.XSUsageMaster, sMSK)
	put(testPrincipal, id.XSUsageSelfSigning, sSSK)
	sig(testPrincipal, sSSK, testPrincipal, sMSK)
	sig(testPrincipal, sMSK, testJill, jUSK)

	phone := &id.Device{UserID: testPrincipal, DeviceID: "PHONE", SigningKey: newKey(t).PublicKey()}
	sig(testPrincipal, phone.SigningKey, testPrincipal, sSSK)
	rogue := &id.Device{UserID: testPrincipal, DeviceID: "ROGUE", SigningKey: newKey(t).PublicKey()}

	gets := func(d *id.Device) bool {
		ts, err := mach.ResolveTrustContext(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		return ts >= mach.SendKeysMinTrust
	}
	if !gets(phone) {
		t.Fatal("Sean's device cross-signed under the pinned master key must receive room keys")
	}
	if gets(rogue) {
		t.Fatal("a device the server added to Sean's account, not cross-signed, must not receive room keys")
	}

	// The server swaps in a new master key for Sean, with its own SSK
	// signing a device of its choosing. Jill's USK never signed it.
	evilMSK, evilSSK := newKey(t).PublicKey(), newKey(t).PublicKey()
	put(testPrincipal, id.XSUsageMaster, evilMSK)
	put(testPrincipal, id.XSUsageSelfSigning, evilSSK)
	sig(testPrincipal, evilSSK, testPrincipal, evilMSK)
	planted := &id.Device{UserID: testPrincipal, DeviceID: "PLANTED", SigningKey: newKey(t).PublicKey()}
	sig(testPrincipal, planted.SigningKey, testPrincipal, evilSSK)
	if gets(planted) {
		t.Fatal("a device under a master key Jill did not sign must not receive room keys")
	}
	if gets(phone) {
		t.Fatal("after a master key swap no device of Sean's may receive keys until setup re-pins")
	}
}
