// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

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
}
