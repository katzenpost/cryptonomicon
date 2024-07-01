// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"encoding/binary"
	"errors"

	"github.com/katzenpost/hpqc/kem"
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

	// σroot ← P-Init(kroot)
	rng, err := NewPRF_PRNG(seed[CKA_SeedSize:])
	if err != nil {
		return nil, err
	}

	// (σroot, k) ← P-Up(σroot, λ)
	// XXX FIX ME
	// outputKey := rng.Up(lambda)

	// v[·] ← λ
	// XXX FIX ME: what does this mean?
	// initialize all vectors to λ?
	// we don't have any λ. or any vectors yet.

	states := make(map[uint32]*ForwardSecureAEAD)

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

/*
Receiving messages: When a ciphertext c = (h, e, `) with header h = (t, T, `) is processed
by Rcv-A, there are two possibilities:
– t ≤ tcur: In this case, ciphertext c pertains to an existing FS-AEAD epoch, in which
case FS-Send is simply called on v[t] to process e. If the maximum number of messages
has been received for session v[t], the session is removed from memory.
– t = tcur + 1 (in which case tcur is odd): Here, the receiver algorithm advances tcur by
incrementing it and processes T with CKA-R. This produces a key I, which is absorbed
into the PRF-PRG to obtain a key k with which to initialize a new epoch v[tcur] as
receiver. Then, e is processed by FS-Rcv on v[tcur]. Note that Rcv also uses FS-Max to
store ` as the maximum number of messages in the previous receive epoch.
*/

// Receive decrypts the ciphertext and returns the plaintext or an error.
func (r *Ratchet) Receive(ciphertext []byte) ([]byte, error) {
	/*
	   Rcv-A (c)
	   (h, e) ← c
	   (t, T, `) ← h
	   req t even and t ≤ tcur + 1
	   if t = tcur + 1
	       tcur ++
	       FS-Max(v[t − 2], `)
	       (γ, I) ← CKA-R(γ, T)
	       (σroot, k) ← P-Up(σroot, I)
	       v[t] ← FS-Init-R(k)
	   (v[t], i, m) ← FS-Rcv(v[t], h, e)
	   if m = ⊥
	       error
	   return (t, i, m)
	*/

	// XXX fix me
	//ad := make([]byte, 32)

	return nil, nil // XXX
}
