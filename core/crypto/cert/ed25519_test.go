// ed25519_test.go - ed25519 certificate tests.
// Copyright (C) 2018  David Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cert

import (
	"bytes"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/sign/eddsa"
	"github.com/stretchr/testify/require"
)

func TestEd25519ExpiredCertificate(t *testing.T) {
	require := require.New(t)

	signingPrivKey, _ := eddsa.Scheme.NewKeypair()

	message := []byte("hello world")

	// expiration six months ago
	expiration := time.Now().AddDate(0, -6, 0).Unix()

	_, err := Sign(signingPrivKey, message, expiration)
	require.Error(err)
}

func TestEd25519Certificate(t *testing.T) {
	require := require.New(t)

	_, ephemeralPubKey := eddsa.Scheme.NewKeypair()
	signingPrivKey, signingPubKey := eddsa.Scheme.NewKeypair()

	// expires 600 years after unix epoch
	expiration := time.Unix(0, 0).AddDate(600, 0, 0).Unix()

	toSign := []byte("hello this is a message")
	certificate, err := Sign(signingPrivKey, toSign, expiration)
	require.NoError(err)

	mesg, err := Verify(signingPubKey, certificate)
	require.NoError(err)
	require.NotNil(mesg)
	require.Equal(mesg, toSign)

	_, err = Verify(ephemeralPubKey, certificate)
	require.Error(err)

}

func TestEd25519BadCertificate(t *testing.T) {
	require := require.New(t)

	signingPrivKey, signingPubKey := eddsa.Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()
	certified := signingPubKey.Bytes()
	certified[3] = 235 // modify the signed data so that the Verify will fail

	certificate, err := Sign(signingPrivKey, certified, expiration)
	require.NoError(err)

	mesg, err := Verify(signingPubKey, certificate)
	require.Error(err)
	require.Equal(ErrBadSignature, err)
	require.Nil(mesg)
}

func TestEd25519WrongCertificate(t *testing.T) {
	require := require.New(t)

	_, ephemeralPubKey := eddsa.Scheme.NewKeypair()
	signingPrivKey, _ := eddsa.Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()
	message := []byte("hi. i am a message.")
	certificate, err := Sign(signingPrivKey, message, expiration)
	require.NoError(err)

	mesg, err := Verify(ephemeralPubKey, certificate)
	require.Error(err)
	require.Nil(mesg)
}

func TestEd25519MultiSignatureCertificate(t *testing.T) {
	require := require.New(t)

	signingPrivKey1, signingPubKey1 := eddsa.Scheme.NewKeypair()
	signingPrivKey2, signingPubKey2 := eddsa.Scheme.NewKeypair()
	signingPrivKey3, signingPubKey3 := eddsa.Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	message := []byte("hello i am a message")

	certificate, err := Sign(signingPrivKey1, message, expiration)
	require.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, certificate)
	require.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, certificate)
	require.NoError(err)

	mesg, err := Verify(signingPubKey1, certificate)
	require.NoError(err)
	require.NotNil(mesg)

	mesg, err = Verify(signingPubKey2, certificate)
	require.NoError(err)
	require.NotNil(mesg)

	mesg, err = Verify(signingPubKey3, certificate)
	require.NoError(err)
	require.NotNil(mesg)
}

func TestEd25519MultiSignatureOrdering(t *testing.T) {
	require := require.New(t)

	signingPrivKey1, _ := eddsa.Scheme.NewKeypair()
	signingPrivKey2, _ := eddsa.Scheme.NewKeypair()
	signingPrivKey3, _ := eddsa.Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()

	message := []byte("this is a message")

	// 1
	certificate1, err := Sign(signingPrivKey1, message, expiration)
	require.NoError(err)
	certificate1, err = SignMulti(signingPrivKey2, certificate1)
	require.NoError(err)
	certificate1, err = SignMulti(signingPrivKey3, certificate1)
	require.NoError(err)

	// 2
	certificate2, err := Sign(signingPrivKey1, message, expiration)
	require.NoError(err)
	certificate2, err = SignMulti(signingPrivKey3, certificate2)
	require.NoError(err)
	certificate2, err = SignMulti(signingPrivKey2, certificate2)
	require.NoError(err)

	require.Equal(certificate1, certificate2)

	// 3
	certificate3, err := Sign(signingPrivKey2, message, expiration)
	require.NoError(err)
	certificate3, err = SignMulti(signingPrivKey3, certificate3)
	require.NoError(err)
	certificate3, err = SignMulti(signingPrivKey1, certificate3)
	require.NoError(err)

	require.Equal(certificate3, certificate2)
}

func TestEd25519VerifyAll(t *testing.T) {
	require := require.New(t)

	signingPrivKey1, signingPubKey1 := eddsa.Scheme.NewKeypair()
	signingPrivKey2, signingPubKey2 := eddsa.Scheme.NewKeypair()
	signingPrivKey3, signingPubKey3 := eddsa.Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()
	message := []byte("this is a message")

	certificate, err := Sign(signingPrivKey1, message, expiration)
	require.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, certificate)
	require.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, certificate)
	require.NoError(err)

	verifiers := []Verifier{signingPubKey1, signingPubKey2, signingPubKey3}
	mesg, err := VerifyAll(verifiers, certificate)
	require.NoError(err)
	require.NotNil(mesg)
}

func TestEd25519VerifyThreshold(t *testing.T) {
	require := require.New(t)

	signingPrivKey1, signingPubKey1 := eddsa.Scheme.NewKeypair()
	signingPrivKey2, signingPubKey2 := eddsa.Scheme.NewKeypair()
	signingPrivKey3, _ := eddsa.Scheme.NewKeypair()
	signingPrivKey4, signingPubKey4 := eddsa.Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()
	message := []byte("this is a message")

	certificate, err := Sign(signingPrivKey1, message, expiration)
	require.NoError(err)

	certificate, err = SignMulti(signingPrivKey2, certificate)
	require.NoError(err)

	certificate, err = SignMulti(signingPrivKey3, certificate)
	require.NoError(err)

	verifiers := []Verifier{signingPubKey1, signingPubKey2, signingPubKey4}
	threshold := 2
	mesg, good, bad, err := VerifyThreshold(verifiers, threshold, certificate)
	require.NoError(err)
	require.NotNil(mesg)
	require.Equal(bad[0].Identity(), signingPrivKey4.Identity())
	hasVerifier := func(verifier Verifier) bool {
		for _, v := range good {
			if bytes.Equal(v.Identity(), verifier.Identity()) {
				return true
			}
		}
		return false
	}
	require.True(hasVerifier(signingPubKey1))
	require.True(hasVerifier(signingPubKey2))
	require.False(hasVerifier(signingPubKey4))
}

func TestEd25519AddSignature(t *testing.T) {
	require := require.New(t)

	signingPrivKey1, _ := eddsa.Scheme.NewKeypair()
	signingPrivKey2, signingPubKey2 := eddsa.Scheme.NewKeypair()

	// expiration in six months
	expiration := time.Now().AddDate(0, 6, 0).Unix()
	message := []byte("this is message")

	certificate, err := Sign(signingPrivKey1, message, expiration)
	require.NoError(err)

	certificate2, err := SignMulti(signingPrivKey2, certificate)
	require.NoError(err)

	sig, err := GetSignature(signingPrivKey2.Identity(), certificate2)
	require.NoError(err)
	require.NotNil(sig)
	certificate3, err := AddSignature(signingPubKey2, *sig, certificate)
	require.NoError(err)

	require.Equal(certificate2, certificate3)
}
