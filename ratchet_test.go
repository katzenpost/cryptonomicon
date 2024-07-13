// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHeaderMarshaling(t *testing.T) {
	ikm := make([]byte, 64)
	_, err := rand.Reader.Read(ikm)
	require.NoError(t, err)

	alice, err := NewCKA("x25519", ikm, true)
	require.NoError(t, err)

	message1, _, err := alice.Send()
	require.NoError(t, err)

	h := &header{
		cur:        123,
		prev:       123,
		ckaMessage: message1,
	}
	blob, err := h.MarshalBinary()
	require.NoError(t, err)

	h2, err := headerFromBinary(alice.scheme, blob)
	require.NoError(t, err)

	require.Equal(t, h.cur, h2.cur)
	require.Equal(t, h.prev, h2.prev)
}

func TestRatchet(t *testing.T) {
	seed := make([]byte, RatchetSeedSize)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	alice, err := New(seed, false)
	require.NoError(t, err)

	bob, err := New(seed, true)
	require.NoError(t, err)

	message1 := []byte("hello Bob")

	ciphertext1 := bob.Send(message1)
	t.Log("bob sent message")

	message1b, err := alice.Receive(ciphertext1)
	require.NoError(t, err)

	require.Equal(t, message1, message1b)
}
