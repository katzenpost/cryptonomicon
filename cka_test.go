// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"crypto/rand"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/stretchr/testify/require"
)

func TestCKAMessageMarshaling(t *testing.T) {
	ikm := make([]byte, 64)
	_, err := rand.Reader.Read(ikm)
	require.NoError(t, err)

	kemName := "x25519"

	alice, err := NewCKA(kemName, ikm, true)
	require.NoError(t, err)

	message1, _, err := alice.Send()
	require.NoError(t, err)

	blob1, err := ccbor.Marshal(message1)
	require.NoError(t, err)

	scheme := schemes.ByName(kemName)
	require.NotNil(t, scheme)

	message2 := &CKAMessage{}
	err = cbor.Unmarshal(blob1, message2)
	require.NoError(t, err)

	estimatedCKAMessageSize := scheme.CiphertextSize() + scheme.PublicKeySize()

	/*
		t.Logf("CKA message size %d, ", len(blob1))
		t.Logf("CKA MESSAGE RAW IS %x", blob1)
		t.Logf("CKA MESSAGE PUB KEY %x", message1.PublicKey)
		t.Logf("CKA MESSAGE CIPHERTEXT %x", message1.Ciphertext)
		t.Logf("estimatedCKAMessageSize %d", estimatedCKAMessageSize)
		t.Logf("diff %d", len(blob1)-estimatedCKAMessageSize)
	*/

	require.Equal(t, len(blob1)-estimatedCKAMessageSize, CBOROverhead)

	require.Equal(t, message1.Ciphertext, message2.Ciphertext)
	require.Equal(t, message1.PublicKey, message2.PublicKey)
}

func TestCKA(t *testing.T) {
	ikm := make([]byte, 64)
	_, err := rand.Reader.Read(ikm)
	require.NoError(t, err)

	alice, err := NewCKA("x25519", ikm, true)
	require.NoError(t, err)
	bob, err := NewCKA("x25519", ikm, false)
	require.NoError(t, err)

	message1, ss1a, err := alice.Send()
	require.NoError(t, err)
	ss1b, err := bob.Receive(message1)
	require.NoError(t, err)
	require.Equal(t, ss1a, ss1b)

	message2, ss2b, err := bob.Send()
	require.NoError(t, err)
	ss2a, err := alice.Receive(message2)
	require.NoError(t, err)
	require.Equal(t, ss2a, ss2b)

	message3, ss3a, err := alice.Send()
	require.NoError(t, err)
	ss3b, err := bob.Receive(message3)
	require.NoError(t, err)
	require.Equal(t, ss3a, ss3b)
}
