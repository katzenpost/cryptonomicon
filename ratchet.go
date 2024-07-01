// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"golang.org/x/crypto/blake2b"
)

const (
	RatchetSeedSize = CKA_SeedSize + PRF_PRNG_Keysize
)

type header struct {
	cur        uint32
	prev       uint32
	ckaMessage *CKAMessage
}

func headerSize(scheme kem.Scheme) int {
	return 4 + 4 + scheme.CiphertextSize() + scheme.PublicKeySize()
}

func headerFromBinary(scheme kem.Scheme, b []byte) (*header, error) {
	cur := binary.BigEndian.Uint32(b[:4])
	prev := binary.BigEndian.Uint32(b[4:8])

	// scheme.PublicKeySize()
	ckaMessageBlob := b[8:]
	ckaMessage, err := ckaMessageFromBinbary(scheme, ckaMessageBlob)
	if err != nil {
		return nil, err
	}

	return &header{
		cur:        cur,
		prev:       prev,
		ckaMessage: ckaMessage,
	}, nil
}

func (h *header) MarshalBinary() ([]byte, error) {
	curRaw := make([]byte, 4)
	binary.BigEndian.PutUint32(curRaw, h.cur)

	prevRaw := make([]byte, 4)
	binary.BigEndian.PutUint32(prevRaw, h.prev)

	ckaMessageBlob, err := h.ckaMessage.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return ckaMessageBlob, nil
}

type Ratchet struct {
	isA bool

	states map[uint32]*ForwardSecureAEAD

	root *PRF_PRNG
	cka  *CKA

	currentMessage *CKAMessage

	prev uint32
	cur  uint32

	scheme kem.Scheme
}

func New(seed []byte, isA bool) (*Ratchet, error) {
	if len(seed) != RatchetSeedSize {
		return nil, errors.New("incorrect Ratchet seed size")
	}

	kemName := "x25519"
	s := schemes.ByName(kemName)
	if s == nil {
		return nil, fmt.Errorf("KEM scheme '%s' not supported", kemName)
	}

	cka, err := NewCKA(kemName, seed[:CKA_SeedSize], isA)
	if err != nil {
		return nil, err
	}

	// σroot ← P-Init(kroot)
	rng, err := NewPRF_PRNG(seed[CKA_SeedSize:])
	if err != nil {
		return nil, err
	}

	// is this a typo in the paper?
	// (σroot, k) ← P-Up(σroot, λ)
	// perhaps should be this:
	// (σroot, λ) ← P-Up(σroot, k)
	// XXX is this correct?
	//lambda := rng.Up(seed)

	// v[·] ← λ
	// XXX FIX ME: what does this mean?
	// initialize all vectors to λ?
	// we don't have v[] entries yet.

	states := make(map[uint32]*ForwardSecureAEAD)

	// v[0] ← FS-Init-R(k)
	hashed := blake2b.Sum512(seed)

	// γ ← CKA-Init-A(kCKA )
	fsAead, err := NewFSAEAD(hashed[:], isA)
	if err != nil {
		return nil, err
	}
	states[0] = fsAead

	// Tcur ← λ
	// XXX what does this mean?

	return &Ratchet{
		// `prv ← 0
		prev: 0,
		// tcur ← 0
		cur: 0,

		scheme: s,
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
		currentMessage, sharedSecret, err := r.cka.Send()
		if err != nil {
			panic(err)
		}
		r.currentMessage = currentMessage

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
	prevRaw := make([]byte, 4)
	binary.BigEndian.PutUint32(prevRaw, r.prev)
	myHeader := &header{
		cur:        r.cur,
		prev:       r.prev,
		ckaMessage: r.currentMessage,
	}
	ad, err := myHeader.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// (v[tcur], e) ← FS-Send(v[tcur], h, m)
	fs := r.states[r.cur]
	_, ciphertext := fs.Send(message, ad)
	return append(ad, ciphertext...)
}

// Receive decrypts the ciphertext and returns the plaintext or an error.
func (r *Ratchet) Receive(ciphertext []byte) ([]byte, error) {
	ad := ciphertext[:headerSize(r.scheme)]
	ciphertext = ciphertext[headerSize(r.scheme):]

	myHeader, err := headerFromBinary(r.scheme, ad)
	if err != nil {
		return nil, err
	}

	// if t = tcur + 1
	if myHeader.cur == r.cur+1 {
		// tcur ++
		r.cur++
		// FS-Max(v[t − 2], `)
		r.states[myHeader.cur].Max(r.prev)
		// (γ, I) ← CKA-R(γ, T)
		sharedSecret, err := r.cka.Receive(myHeader.ckaMessage)
		if err != nil {
			return nil, err
		}
		// (σroot, k) ← P-Up(σroot, I)
		key := r.root.Up(sharedSecret)
		// v[t] ← FS-Init-R(k)
		r.states[myHeader.cur], err = NewFSAEAD(key, false)
		if err != nil {
			return nil, err
		}
	}

	// (v[t], i, m) ← FS-Rcv(v[t], h, e)
	// XXX I'm not sure if this is correct
	plaintext, _, err := r.states[myHeader.cur].Receive(ciphertext, ad, r.cur)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
