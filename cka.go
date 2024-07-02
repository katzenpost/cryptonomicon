// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"fmt"
	"hash"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
)

const (
	CKA_SeedSize = 64
)

var (
	hkdfCKALabel = []byte("cka hkdf constructor")
)

// CKAState is a state type used by the CKA.
type CKAState struct {
	// PublicKey is the KEM public key.
	PublicKey kem.PublicKey
	// PrivateKey is the KEM private key.
	PrivateKey kem.PrivateKey
}

// NewCKAState constructs a new SKAState given a keypair.
func NewCKAState(publicKey kem.PublicKey, privateKey kem.PrivateKey) *CKAState {
	return &CKAState{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}
}

// CKAMessage encapsulates a CKA Message.
type CKAMessage struct {
	// PublicKey is the new KEM public key.
	PublicKey kem.PublicKey
	// Ciphertext is the new KEM ciphertext.
	Ciphertext []byte
}

func ckaMessageFromBinary(scheme kem.Scheme, b []byte) (*CKAMessage, error) {
	offset := scheme.PublicKeySize()
	pubkeyRaw := b[:offset]
	pubkey, err := scheme.UnmarshalBinaryPublicKey(pubkeyRaw)
	if err != nil {
		return nil, err
	}
	ciphertext := b[offset:]

	return &CKAMessage{
		PublicKey:  pubkey,
		Ciphertext: ciphertext,
	}, nil
}

func (c *CKAMessage) MarshalBinary() ([]byte, error) {
	pubkeyBlob, err := c.PublicKey.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(pubkeyBlob, c.Ciphertext...), nil
}

// CKA is also known as Continuous Key Agreement
// described in detail in the paper:
//
// https://eprint.iacr.org/2018/1037.pdf
// The Double Ratchet: Security Notions, Proofs,
// and Modularization for the Signal Protocol
// Page 21 section 'CKA from KEMs.'
type CKA struct {
	scheme kem.Scheme
	state  *CKAState
}

// NewCKA returns a newly constructed CKA.
func NewCKA(kemName string, ikm []byte, isInitiator bool) (*CKA, error) {
	if len(ikm) != CKA_SeedSize {
		return nil, fmt.Errorf("ikm must be size %d", CKA_SeedSize)
	}

	s := schemes.ByName(kemName)
	if s == nil {
		return nil, fmt.Errorf("KEM scheme '%s' not supported", kemName)
	}

	seed := make([]byte, s.SeedSize())
	myHash := func() hash.Hash {
		h, err := blake2b.New512(nil)
		if err != nil {
			panic(err)
		}
		return h
	}
	h := hkdf.New(myHash, ikm, nil, hkdfCKALabel)
	_, err := h.Read(seed)
	if err != nil {
		panic(err)
	}

	pubkey, privkey := s.DeriveKeyPair(seed)
	var state *CKAState
	if isInitiator {
		state = NewCKAState(pubkey, nil)
	} else {
		state = NewCKAState(nil, privkey)
	}

	return &CKA{
		scheme: s,
		state:  state,
	}, nil
}

// Send performs the CKA Send operation.
func (c *CKA) Send() (*CKAMessage, []byte, error) {
	ct, sharedSecret, err := c.scheme.Encapsulate(c.state.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubkey, privkey, err := c.scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	m := &CKAMessage{
		Ciphertext: ct,
		PublicKey:  pubkey,
	}
	c.state.PrivateKey = privkey
	return m, sharedSecret, nil
}

// Receive performs the CKA Receive operation.
func (c *CKA) Receive(message *CKAMessage) ([]byte, error) {
	sharedSecret, err := c.scheme.Decapsulate(c.state.PrivateKey, message.Ciphertext)
	if err != nil {
		return nil, err
	}
	c.state.PublicKey = message.PublicKey
	return sharedSecret, nil
}
