// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"errors"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
)

const (
	PRF_PRNG_Keysize = blake2b.Size
)

var (
	hkdfInitPRFPRNGLabel = []byte("prf prng hkdf init")
)

type PRF_PRNG struct {
	state []byte
}

func blakeHash() hash.Hash {
	h, err := blake2b.New512(nil)
	if err != nil {
		panic(err)
	}
	return h
}

func NewPRF_PRNG(key []byte) (*PRF_PRNG, error) {
	if len(key) != PRF_PRNG_Keysize {
		return nil, errors.New("wrong key size")
	}

	h := hkdf.New(blakeHash, key, nil, hkdfInitPRFPRNGLabel)
	state := make([]byte, 64)
	_, err := h.Read(state)
	if err != nil {
		panic(err)
	}

	return &PRF_PRNG{
		state: state,
	}, nil
}

func (p *PRF_PRNG) Up(b []byte) []byte {
	// func New(hash func() hash.Hash, secret, salt, info []byte) io.Reader {
	h := hkdf.New(blakeHash, b, p.state, hkdfInitPRFPRNGLabel)

	stream := make([]byte, (PRF_PRNG_Keysize * 2))
	_, err := h.Read(stream)
	if err != nil {
		panic(err)
	}

	// Update state with the first half of the stream
	p.state = stream[:PRF_PRNG_Keysize]

	return stream[PRF_PRNG_Keysize:]
}
