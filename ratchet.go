// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2b"
)

const (
	RatchetSeedSize = CKA_SeedSize + PRF_PRNG_Keysize
)

type Ratchet struct {
	isA    bool
	states map[uint32]*ForwardSecureAEAD
	root   *PRF_PRNG
	cka    *CKA
	prev   uint32
	cur    uint32
}

func New(seed []byte, isA bool) (*Ratchet, error) {
	if len(seed) != RatchetSeedSize {
		return nil, errors.New("incorrect Ratchet seed size")
	}

	kemName := "x25519"
	cka, err := NewCKA(kemName, seed[:CKA_SeedSize], isA)
	if err != nil {
		return nil, err
	}

	rng, err := NewPRF_PRNG(seed[CKA_SeedSize:])
	if err != nil {
		return nil, err
	}

	states := make(map[uint32]*ForwardSecureAEAD)

	// v[·] ← λ
	// XXX FIX ME
	lambda := make([]byte, 64)
	rng.Up(lambda)

	// v[0] ← FS-Init-R(k)
	hashed := blake2b.Sum512(seed)
	fsAead, err := NewFSAEAD(hashed[:], isA)
	if err != nil {
		return nil, err
	}
	states[0] = fsAead

	return &Ratchet{
		isA:    isA,
		states: states,
		root:   rng,
		cka:    cka,
	}, nil
}

// Send comsumes the given message and returns a ciphertext.
func (r *Ratchet) Send(message []byte) []byte {
	// if tcur is even
	if (r.cur % 2) == 0 {

		// `prv ← FS-Stop(v[tcur − 1])
		state, ok := r.states[r.cur-1]
		if !ok {
			panic("failed to find map entry")
		}
		r.prev = state.Stop()

		// tcur++
		r.cur++

		// (γ, Tcur, I) ←$ CKA-S(γ)
		// message, sharedSecret, err := r.cka.Send()
		_, sharedSecret, err := r.cka.Send()
		if err != nil {
			panic(err)
		}

		// (σroot, k) ← P-Up(σroot, I)
		seed := r.root.Up(sharedSecret)

		// v[tcur] ← FS-Init-S(k)
		fs, err := NewFSAEAD(seed, r.isA)
		if err != nil {
			panic(err)
		}
		r.states[r.cur] = fs
	}

	// h ← (tcur, Tcur, `prv)
	countRaw := make([]byte, 4)
	binary.BigEndian.PutUint32(countRaw, r.cur)

	// XXX fix me
	ad := make([]byte, 32)

	// (v[tcur], e) ← FS-Send(v[tcur], h, m)
	fs := r.states[r.cur]
	_, ciphertext := fs.Send(message, ad)
	return ad, ciphertext
}

func (r *Ratchet) Receive(ciphertext []byte) {

	// (h, e) ← c
	// XXX fix me
	ad := make([]byte, 32)

}
