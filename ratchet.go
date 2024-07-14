// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
)

const (
	RatchetSeedSize = CKA_SeedSize + PRF_PRNG_Keysize
)

// Create reusable EncMode interface with immutable options, safe for concurrent use.
var ccbor cbor.EncMode

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
	ckaMessageBlob := b[8:]
	ckaMessage, err := ckaMessageFromBinary(scheme, ckaMessageBlob)
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

	return append(append(curRaw, prevRaw...), ckaMessageBlob...), nil
}

type Ratchet struct {
	isA bool

	states map[uint32]*ForwardSecureAEAD

	root *PRF_PRNG
	cka  *CKAState

	currentMessage *CKAMessage

	prev uint32
	cur  uint32

	schemeName string
}

func FromBlob(b []byte) (*Ratchet, error) {
	r := &Ratchet{
		states: make(map[uint32]*ForwardSecureAEAD),
		root:   &PRF_PRNG{},
		cka:    &CKAState{},
	}
	err := cbor.Unmarshal(b, r)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Ratchet) Marshal() ([]byte, error) {
	return ccbor.Marshal(r)
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

	// (kroot , kCKA ) ← k
	kroot := seed[:PRF_PRNG_Keysize]
	kCKA := seed[PRF_PRNG_Keysize:]

	// σroot ← P-Init(kroot)
	rng, err := NewPRF_PRNG(kroot)
	if err != nil {
		return nil, err
	}

	// (σroot, k) ← P-Up(σroot, λ)
	// Here λ refers to the default vaule which
	// all ratchets will use.
	labmda := make([]byte, 64)
	_ = rng.Up(labmda)

	// v[·] ← λ
	states := make(map[uint32]*ForwardSecureAEAD)

	// γ ← CKA-Init-A(kCKA )
	cka, err := NewCKA(kemName, kCKA, isA)
	if err != nil {
		return nil, err
	}

	return &Ratchet{
		// `prv ← 0
		prev: 0,
		// tcur ← 0
		cur: 0,

		schemeName: s.Name(),
		isA:        isA,
		states:     states,
		root:       rng,
		cka:        cka,
	}, nil
}

// Send comsumes the given message and returns a ciphertext.
func (r *Ratchet) Send(message []byte) []byte {
	checkEven := false
	if r.isA == true {
		checkEven = true
	}
	isEven := false
	if (r.cur % 2) == 0 {
		isEven = true
	}
	doUpdate := false
	switch {
	case checkEven == true && isEven == true:
		doUpdate = true
	case checkEven == false && isEven == false:
		doUpdate = true
	}

	if doUpdate {
		if r.cur != 0 && r.cur != 1 {
			// `prv ← FS-Stop(v[tcur − 1])
			state, ok := r.states[r.cur-1]
			if !ok {
				panic("failed to find map entry")
			}
			r.prev = state.Stop()
		}

		// tcur++
		r.cur++

		// (γ, Tcur, I) ←$ CKA-S(γ)
		currentMessage, sharedSecret, err := r.cka.Send()
		r.currentMessage = currentMessage
		if err != nil {
			panic(err)
		}

		// (σroot, k) ← P-Up(σroot, I)
		seed := r.root.Up(sharedSecret)

		// v[tcur] ← FS-Init-S(k)
		fs, err := NewFSAEAD(seed, true)
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
	ad, ciphertext := fs.Send(message, ad)
	return append(ad, ciphertext...)
}

func assert(b bool) {
	if !b {
		panic("assertion failure")
	}
}

// Receive decrypts the ciphertext and returns the plaintext or an error.
func (r *Ratchet) Receive(ciphertext []byte) ([]byte, error) {
	// (h, e) ← c
	ad := ciphertext[:headerSize(r.cka.scheme)+4]
	ciphertext = ciphertext[4+headerSize(r.cka.scheme):]

	// (t, T, `) ← h
	myHeader, err := headerFromBinary(r.cka.scheme, ad[4:])
	if err != nil {
		return nil, err
	}

	// req t even and t ≤ tcur + 1
	if r.isA {
		assert(myHeader.cur%2 == 0 && myHeader.cur <= (r.cur+1))
	} else {
		assert(myHeader.cur%2 == 1 && myHeader.cur <= (r.cur+1))
	}

	// if t = tcur + 1
	if myHeader.cur == r.cur+1 {
		// tcur ++
		r.cur++

		// FS-Max(v[t − 2], `)
		if r.cur != 1 && r.cur != 2 {
			r.states[myHeader.cur-2].Max(r.prev)
		}

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
	plaintext, err := r.states[myHeader.cur].Receive(ciphertext, ad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func init() {
	var err error
	opts := cbor.CanonicalEncOptions()
	ccbor, err = opts.EncMode()
	if err != nil {
		panic(err)
	}
}
