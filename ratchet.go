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
	EpochCount    uint32
	PrevSendCount uint32
	CKAMessage    *CKAMessage
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
		EpochCount:    cur,
		PrevSendCount: prev,
		CKAMessage:    ckaMessage,
	}, nil
}

func (h *header) MarshalBinary() ([]byte, error) {
	curRaw := make([]byte, 4)
	binary.BigEndian.PutUint32(curRaw, h.EpochCount)

	prevRaw := make([]byte, 4)
	binary.BigEndian.PutUint32(prevRaw, h.PrevSendCount)

	ckaMessageBlob, err := h.CKAMessage.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return append(append(curRaw, prevRaw...), ckaMessageBlob...), nil
}

type Ratchet struct {
	IsA bool

	States map[uint32]*ForwardSecureAEAD

	Root     *PRF_PRNG
	CKAState *CKAState

	CurrentMessage *CKAMessage

	PrevSendCount uint32
	EpochCount    uint32

	KEMSchemeName string
}

func FromBlob(b []byte) (*Ratchet, error) {
	r := &Ratchet{
		States:   make(map[uint32]*ForwardSecureAEAD),
		Root:     &PRF_PRNG{},
		CKAState: &CKAState{},
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
		PrevSendCount: 0,
		// tcur ← 0
		EpochCount: 0,

		KEMSchemeName: s.Name(),
		IsA:           isA,
		States:        states,
		Root:          rng,
		CKAState:      cka,
	}, nil
}

// Send comsumes the given message and returns a ciphertext.
func (r *Ratchet) Send(message []byte) []byte {
	checkEven := false
	if r.IsA == true {
		checkEven = true
	}
	isEven := false
	if (r.EpochCount % 2) == 0 {
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
		if r.EpochCount != 0 && r.EpochCount != 1 {
			// `prv ← FS-Stop(v[tcur − 1])
			state, ok := r.States[r.EpochCount-1]
			if !ok {
				panic("failed to find map entry")
			}
			r.PrevSendCount = state.Stop()
		}

		// tcur++
		r.EpochCount++

		// (γ, Tcur, I) ←$ CKA-S(γ)
		currentMessage, sharedSecret, err := r.CKAState.Send()
		r.CurrentMessage = currentMessage
		if err != nil {
			panic(err)
		}

		// (σroot, k) ← P-Up(σroot, I)
		seed := r.Root.Up(sharedSecret)

		// v[tcur] ← FS-Init-S(k)
		fs, err := NewFSAEAD(seed, true)
		if err != nil {
			panic(err)
		}
		r.States[r.EpochCount] = fs
	}

	// h ← (tcur, Tcur, `prv)
	countRaw := make([]byte, 4)
	binary.BigEndian.PutUint32(countRaw, r.EpochCount)
	prevRaw := make([]byte, 4)
	binary.BigEndian.PutUint32(prevRaw, r.PrevSendCount)
	myHeader := &header{
		EpochCount:    r.EpochCount,
		PrevSendCount: r.PrevSendCount,
		CKAMessage:    r.CurrentMessage,
	}
	ad, err := myHeader.MarshalBinary()
	if err != nil {
		panic(err)
	}

	// (v[tcur], e) ← FS-Send(v[tcur], h, m)
	fs := r.States[r.EpochCount]
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
	scheme := schemes.ByName(r.CKAState.KEMSchemeName)
	if scheme == nil {
		panic("nil KEM scheme")
	}

	// (h, e) ← c
	ad := ciphertext[:headerSize(scheme)+4]
	ciphertext = ciphertext[4+headerSize(scheme):]

	// (t, T, `) ← h
	myHeader, err := headerFromBinary(scheme, ad[4:])
	if err != nil {
		return nil, err
	}

	// req t even and t ≤ tcur + 1
	if r.IsA {
		assert(myHeader.EpochCount%2 == 0 && myHeader.EpochCount <= (r.EpochCount+1))
	} else {
		assert(myHeader.EpochCount%2 == 1 && myHeader.EpochCount <= (r.EpochCount+1))
	}

	// if t = tcur + 1
	if myHeader.EpochCount == r.EpochCount+1 {
		// tcur ++
		r.EpochCount++

		// FS-Max(v[t − 2], `)
		if r.EpochCount != 1 && r.EpochCount != 2 {
			r.States[myHeader.EpochCount-2].Max(r.PrevSendCount)
		}

		// (γ, I) ← CKA-R(γ, T)
		sharedSecret, err := r.CKAState.Receive(myHeader.CKAMessage)
		if err != nil {
			return nil, err
		}
		// (σroot, k) ← P-Up(σroot, I)
		key := r.Root.Up(sharedSecret)
		// v[t] ← FS-Init-R(k)
		r.States[myHeader.EpochCount], err = NewFSAEAD(key, false)
		if err != nil {
			return nil, err
		}
	}

	// (v[t], i, m) ← FS-Rcv(v[t], h, e)
	plaintext, err := r.States[myHeader.EpochCount].Receive(ciphertext, ad)
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
