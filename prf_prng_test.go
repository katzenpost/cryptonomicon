// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_PRF_PRNG_SmokeTest(t *testing.T) {
	key := make([]byte, PRF_PRNG_Keysize)
	_, err := rand.Reader.Read(key)
	require.NoError(t, err)

	p, err := NewPRF_PRNG(key)
	require.NoError(t, err)

	key2 := make([]byte, PRF_PRNG_Keysize)
	_, err = rand.Reader.Read(key2)
	require.NoError(t, err)

	key3 := p.Up(key2)
	key4 := p.Up(key2)
	require.NotEqual(t, key3, key4)
}
