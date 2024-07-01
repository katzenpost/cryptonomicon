// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

func Test_FS_AEAD(t *testing.T) {
	seed := make([]byte, SeedSize)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	// alice and bob
	alice, err := NewFSAEAD(seed, true)
	require.NoError(t, err)

	bob, err := NewFSAEAD(seed, false)
	require.NoError(t, err)

	// first message from alice to bob

	message1a := make([]byte, 32)
	_, err = rand.Reader.Read(message1a)
	require.NoError(t, err)

	ad1 := make([]byte, 32)
	_, err = rand.Reader.Read(ad1)
	require.NoError(t, err)

	count1, ciphertext1 := alice.Send(message1a, ad1)
	require.Equal(t, count1, uint32(1))

	message1b, count1b, err := bob.Receive(ciphertext1, ad1, count1)
	require.NoError(t, err)
	require.Equal(t, message1a, message1b)
	require.Equal(t, count1, count1b)

	// second message from alice to bob

	message2a := make([]byte, 32)
	_, err = rand.Reader.Read(message2a)
	require.NoError(t, err)

	ad2 := make([]byte, 32)
	_, err = rand.Reader.Read(ad2)
	require.NoError(t, err)

	count2, ciphertext2 := alice.Send(message2a, ad2)
	require.Equal(t, count1, uint32(1))

	message2b, count2b, err := bob.Receive(ciphertext2, ad2, count2)
	require.NoError(t, err)
	require.Equal(t, message2a, message2b)
	require.Equal(t, count2, count2b)
}
