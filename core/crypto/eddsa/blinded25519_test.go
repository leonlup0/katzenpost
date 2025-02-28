package eddsa

import (
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"math/rand"
	"testing"
	"testing/quick"
)

var identity_element = [32]byte{1, 0}

func check_public_key(pk *PublicKey) bool {
	// here we do scalar multiplication with L as the scalar;
	// the result should be 1 if the public key is valid.
	var result [32]byte
	order_64 := [64]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c,
		0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}
	order_sc, _ := new(edwards25519.Scalar).SetUniformBytes(order_64[:])
	pkA_n, _ := new(edwards25519.Point).SetBytes(pk.Bytes())
	pkA_n.ScalarMult(order_sc, pkA_n)
	copy(result[:], pkA_n.Bytes())
	// non-constant time comparison, only for use in the test suite:
	return (identity_element == result)
}

func bothWork(assertx *assert.Assertions, t require.TestingT, rng io.Reader) bool {
	assert := assertx
	unblinded, err := NewKeypair(rng)
	require.NoError(t, err, "NewKeypair(1)")
	assert.Equal(true, check_public_key(unblinded.PublicKey()))

	factor := make([]byte, BlindFactorSize)
	rng.Read(factor[:])
	f1_blind_secret := unblinded.Blind(factor)
	f1_blind_public := unblinded.PublicKey().Blind(factor)
	f1_derived_public := f1_blind_secret.PublicKey()
	assert.Equal(f1_blind_public, f1_derived_public)

	// check public keys: multiply by L and verify we get identity element
	assert.NotEqual(identity_element, unblinded.PublicKey())
	assert.NotEqual(identity_element, f1_blind_public)

	// Check that using the same factor to blind two different keys
	// results in distinct secret + public keys (ie we don't always just return
	// the same secret/public pair)
	unblinded_x, err := NewKeypair(rng)
	require.NoError(t, err, "NewKeypair(2)")
	assert.NotEqual(unblinded_x.Bytes(), unblinded.Bytes())
	f1_blind_public_x := unblinded_x.PublicKey().Blind(factor)
	f1_blind_secret_x := unblinded_x.Blind(factor)
	assert.NotEqual(f1_blind_public, f1_blind_public_x)
	f1_derived_public_x := f1_blind_secret_x.PublicKey()
	assert.Equal(f1_blind_public_x, f1_derived_public_x)

	factor2 := make([]byte, BlindFactorSize)
	rng.Read(factor2)
	// we just need to ensure that the factors are different,
	// ie we could copy factor and xor a byte in the range 1..30
	// note that factor gets clamped, so we can't use[0] or [31] here
	assert.NotEqual(factor, factor2)
	f2_blind_secret := unblinded.Blind(factor2)
	f2_blind_public := unblinded.PublicKey().Blind(factor2)
	f2_derived_public := f2_blind_secret.PublicKey()
	assert.Equal(f2_blind_public, f2_derived_public)
	assert.NotEqual(f2_blind_public, f1_blind_public)

	assert.Equal(true, check_public_key(f1_blind_public))
	assert.Equal(true, check_public_key(f1_blind_public_x))
	assert.Equal(true, check_public_key(f2_blind_public))

	// Check signature creation and validation:
	msg := [5]byte{'a', 'b', 'c', 'd', 'e'}
	msg_x := [5]byte{'a', 'b', 'c', 'd', 'x'}
	f1_sig := f1_blind_secret.Sign(msg[:])
	f2_sig := f2_blind_secret.Sign(msg[:])
	f1_res1 := f1_blind_public.Verify(f1_sig[:], msg[:])
	f2_res1 := f2_blind_public.Verify(f2_sig[:], msg[:])
	assert.Equal(true, f1_res1)
	assert.Equal(true, f2_res1)

	// signature: (R,s)  ;  check that s < L:
	// the new edwards25519 library doesn't export ScMinimal (scMinimal),
	// but it carries the function under the name "isReduced" which is
	// called from Scalar.SetCanonicalBytes(), so by looking at the (err)
	// from that we can determine the outcome:
	// nil | ScMinimal(s) === true
	// err | ScMinimal(s) === false
	f1_sig_s := [32]byte{}
	copy(f1_sig_s[:], f1_sig[32:])
	// old: assert.Equal(true, edwards25519.ScMinimal(&f1_sig_s))
	_, scMinimal := new(edwards25519.Scalar).SetCanonicalBytes(f1_sig_s[:])
	assert.Equal(nil, scMinimal)
	f2_sig_s := [32]byte{}
	copy(f2_sig_s[:], f2_sig[32:])
	_, scMinimal = new(edwards25519.Scalar).SetCanonicalBytes(f2_sig_s[:])
	//assert.Equal(true, edwards25519.ScMinimal(&f2_sig_s))
	assert.Equal(nil, scMinimal)

	// Check that giving arguments in wrong order doesn't work:
	f2_res2_wrong_arg_order := f2_blind_public.Verify(msg[:], f2_sig[:])
	assert.Equal(false, f2_res2_wrong_arg_order)

	// Check that we can't verify messages with the other's PK:
	f1_res3 := f1_blind_public.Verify(f2_sig[:], msg[:])
	f2_res3 := f2_blind_public.Verify(f1_sig[:], msg[:])
	assert.Equal(false, f1_res3)
	assert.Equal(false, f2_res3)

	// Check that the signature contains the message:
	f1_res4 := f1_blind_public.Verify(f1_sig[:], msg_x[:])
	assert.Equal(false, f1_res4)

	// Checking a random "signature" should obviously fail:
	random_sig := [64]byte{}
	f1_res5 := f1_blind_public.Verify(random_sig[:], msg[:])
	assert.Equal(false, f1_res5)

	return true
}

func TestBlinding(t *testing.T) {
	assertx := assert.New(t)
	rng := rand.New(rand.NewSource(0))
	config := &quick.Config{Rand: rng}
	assert_bothwork := func() bool { return bothWork(assertx, t, rng) }
	if err := quick.Check(assert_bothwork, config); err != nil {
		t.Error("failed bothwork", err)
	}
}
