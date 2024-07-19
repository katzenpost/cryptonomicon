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

func TestHeaderMarshaling(t *testing.T) {
	ikm := make([]byte, 64)
	_, err := rand.Reader.Read(ikm)
	require.NoError(t, err)

	kemName := "x25519"
	alice, err := NewCKA(kemName, ikm, true)
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

	scheme := schemes.ByName(kemName)
	require.NotNil(t, scheme)

	h2, err := headerFromBinary(scheme, blob)
	require.NoError(t, err)

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

	t.Logf("len aliceBlob %d %x", len(aliceBlob), aliceBlob)

	aliceNew, err := FromBlob(aliceBlob)
	require.NoError(t, err)

	message2 := []byte("hello Alice")
	ciphertext2 := aliceNew.Send(message2)
	message2b, err := bob.Receive(ciphertext2)
	require.NoError(t, err)
	require.Equal(t, message2, message2b)

}
