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
	CBOROverhead = 26
)

var (
	hkdfCKALabel = []byte("cka hkdf constructor")
)

// CKAState is a state type used by the CKA.
type CKAState struct {
	// PublicKey is the KEM public key.
	PublicKey []byte

	// PrivateKey is the KEM private key.
	PrivateKey []byte

	// KEMSchemeName is the unique name for the KEM scheme being used
	// from the HPQC cryptography library.
	KEMSchemeName string
}

// NewCKAState constructs a new SKAState given a keypair.
func NewCKAState(publicKey kem.PublicKey, privateKey kem.PrivateKey, kemName string) (*CKAState, error) {
	s := schemes.ByName(kemName)
	if s == nil {
		return nil, fmt.Errorf("KEM scheme '%s' not supported", kemName)
	}
	state := &CKAState{
		KEMSchemeName: kemName,
	}
	if publicKey != nil {
		pubblob, err := publicKey.MarshalBinary()
		if err != nil {
			return nil, err
		}
		state.PublicKey = pubblob
	}
	if privateKey != nil {
		privblob, err := privateKey.MarshalBinary()
		if err != nil {
			return nil, err
		}
		state.PrivateKey = privblob
	}
	return state, nil
}

// CKAMessage encapsulates a CKA Message.
type CKAMessage struct {
	// PublicKey is the new KEM public key.
	PublicKey []byte
	// Ciphertext is the new KEM ciphertext.
	Ciphertext []byte
}

// NewCKA returns a newly constructed CKA.
func NewCKA(kemName string, ikm []byte, isInitiator bool) (*CKAState, error) {
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
	if isInitiator {
		return NewCKAState(pubkey, nil, kemName)
	} else {
		return NewCKAState(nil, privkey, kemName)
	}
}

// Send performs the CKA Send operation.
func (c *CKAState) Send() (*CKAMessage, []byte, error) {
	scheme := schemes.ByName(c.KEMSchemeName)
	if scheme == nil {
		panic("nil KEM scheme")
	}
	publicKey, err := scheme.UnmarshalBinaryPublicKey(c.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	ct, sharedSecret, err := scheme.Encapsulate(publicKey)
	if err != nil {
		return nil, nil, err
	}
	pubkey, privkey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	pubblob, err := pubkey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	m := &CKAMessage{
		Ciphertext: ct,
		PublicKey:  pubblob,
	}
	c.PrivateKey, err = privkey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	return m, sharedSecret, nil
}

// Receive performs the CKA Receive operation.
func (c *CKAState) Receive(message *CKAMessage) ([]byte, error) {
	scheme := schemes.ByName(c.KEMSchemeName)
	if scheme == nil {
		panic("nil KEM scheme")
	}
	privateKey, err := scheme.UnmarshalBinaryPrivateKey(c.PrivateKey)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := scheme.Decapsulate(privateKey, message.Ciphertext)
	if err != nil {
		return nil, err
	}
	c.PublicKey = message.PublicKey
	_, err = scheme.UnmarshalBinaryPublicKey(message.PublicKey)
	if err != nil {
		return nil, err
	}
	return sharedSecret, nil
}
