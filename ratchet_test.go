// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/stretchr/testify/require"
)

var (
	kamSchemeName = "Xwing" // pick your favorite hybrid post quantum KEM
)

func TestHeaderMarshaling(t *testing.T) {
	ikm := make([]byte, 64)
	_, err := rand.Reader.Read(ikm)
	require.NoError(t, err)

	kamSchemeName := "x25519"
	alice, err := NewCKA(kamSchemeName, ikm, true)
	require.NoError(t, err)

	message1, _, err := alice.Send()
	require.NoError(t, err)

	h := &header{
		EpochCount:    123,
		PrevSendCount: 123,
		CKAMessage:    message1,
	}
	blob, err := h.MarshalBinary()
	require.NoError(t, err)

	scheme := schemes.ByName(kamSchemeName)
	require.NotNil(t, scheme)

	h2, err := headerFromBinary(scheme, blob)
	require.NoError(t, err)

	require.Equal(t, len(blob), headerSize(scheme))

	require.Equal(t, h.EpochCount, h2.EpochCount)
	require.Equal(t, h.PrevSendCount, h2.PrevSendCount)
}

func TestRatchet(t *testing.T) {
	seed := make([]byte, RatchetSeedSize)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	alice, err := New(seed, true)
	require.NoError(t, err)
	bob, err := New(seed, false)
	require.NoError(t, err)

	message1 := []byte("hello Bob")
	ciphertext1 := alice.Send(message1)
	message1b, err := bob.Receive(ciphertext1)
	require.NoError(t, err)
	require.Equal(t, message1, message1b)

	message2 := []byte("hello Alice")
	ciphertext2 := bob.Send(message2)
	message2b, err := alice.Receive(ciphertext2)
	require.NoError(t, err)
	require.Equal(t, message2, message2b)
}

func TestRatchetMarshaling(t *testing.T) {
	seed := make([]byte, RatchetSeedSize)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	alice, err := New(seed, true)
	require.NoError(t, err)
	bob, err := New(seed, false)
	require.NoError(t, err)

	message1 := []byte("hello Bob")
	ciphertext1 := alice.Send(message1)
	message1b, err := bob.Receive(ciphertext1)
	require.NoError(t, err)
	require.Equal(t, message1, message1b)

	aliceBlob, err := alice.Marshal()
	require.NoError(t, err)

	aliceNew, err := FromBlob(aliceBlob)
	require.NoError(t, err)
	require.NotNil(t, aliceNew)

	message2 := []byte("hello Alice")
	ciphertext2 := aliceNew.Send(message2)
	message2b, err := bob.Receive(ciphertext2)
	require.NoError(t, err)
	require.Equal(t, message2, message2b)
}

const maxMissingMessages = 3

func pairedRatchet(t *testing.T) (*Ratchet, *Ratchet) {
	seed := make([]byte, RatchetSeedSize)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	alice, err := New(seed, true)
	require.NoError(t, err)
	bob, err := New(seed, false)
	require.NoError(t, err)

	return alice.WithMax(maxMissingMessages), bob.WithMax(maxMissingMessages)
}

func reinitRatchet(t *testing.T, r *Ratchet) *Ratchet {
	state, err := r.Marshal()
	require.NoError(t, err)
	r.Reset()

	newR, err := FromBlob(state)
	require.NoError(t, err)

	return newR
}
