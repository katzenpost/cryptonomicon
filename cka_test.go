// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

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
