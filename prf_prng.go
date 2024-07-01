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
	hkdfInitLabel = []byte("prf prng hkdf init")
)

type PRF_PRNG struct {
	state []byte
}

func NewPRF_PRNG(key []byte) (*PRF_PRNG, error) {
	if len(key) != PRF_PRNG_Keysize {
		return nil, errors.New("wrong key size")
	}

	myHash := func() hash.Hash {
		h, err := blake2b.New512(nil)
		if err != nil {
			panic(err)
		}
		return h
	}

	h := hkdf.New(myHash, key, nil, hkdfInitLabel)
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
	myHash := func() hash.Hash {
		h, err := blake2b.New512(nil)
		if err != nil {
			panic(err)
		}
		return h
	}

	h := hkdf.New(myHash, b, p.state, hkdfInitLabel)

	stream := make([]byte, (PRF_PRNG_Keysize + len(b)))
	_, err := h.Read(stream)
	if err != nil {
		panic(err)
	}

	q, err := NewPRF_PRNG(stream[:PRF_PRNG_Keysize])
	if err != nil {
		panic(err)
	}
	p.state = q.state

	return stream[PRF_PRNG_Keysize:]
}
