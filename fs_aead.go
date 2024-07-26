// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"hash"

	"gitlab.com/yawning/bsaes.git"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/katzenpost/hpqc/util"
)

const (
	// StreamKeyLength is the key size of the stream cipher in bytes.
	StreamKeyLength = 32

	// StreamIVLength is the IV size of the stream cipher in bytes.
	StreamIVLength = 16

	symmetricKeySize = chacha20poly1305.KeySize
	nonceSize        = chacha20poly1305.NonceSize

	// FSAEADSeedLength is the length of the seed for creating a new FS-AEAD
	FSAEADSeedLength = StreamKeyLength + StreamIVLength + symmetricKeySize

	defaultMaxReceive = 3
	defaultMaxSend    = 3

	SeedSize = 64
)

var (
	prgKeyLabel = []byte("PRG key")
	prgIVLabel  = []byte("PRG IV")
)

type resetable interface {
	Reset()
}

// Stream is the Sphinx stream cipher.
type Stream struct {
	Key *[StreamKeyLength]byte
	Iv  *[StreamIVLength]byte
}

// NewStream returns a new Stream implementing the Sphinx Stream Cipher with
// the provided key and IV.
func NewStream(key *[StreamKeyLength]byte, iv *[StreamIVLength]byte) *Stream {
	return &Stream{
		Key: key,
		Iv:  iv,
	}
}

// KeyStream fills the buffer dst with key stream output.
func (s *Stream) KeyStream(dst []byte) {
	blk, err := bsaes.NewCipher(s.Key[:])
	if err != nil {
		// Not covered by unit tests because this indicates a bug in bsaes.
		panic("crypto/NewStream: failed to create AES instance: " + err.Error())
	}
	cipher := cipher.NewCTR(blk, s.Iv[:])

	// TODO: Add a fast path for implementations that support it, to
	// shave off the memset and XOR.
	util.ExplicitBzero(dst)
	cipher.XORKeyStream(dst, dst)
}

// Reset clears the Stream instance such that no sensitive data is left in
// memory.
func (s *Stream) Reset() {
	blk, err := bsaes.NewCipher(s.Key[:])
	if err != nil {
		// Not covered by unit tests because this indicates a bug in bsaes.
		panic("crypto/NewStream: failed to create AES instance: " + err.Error())
	}
	cipher := cipher.NewCTR(blk, s.Iv[:])

	// bsaes's ctrAble implementation exposes this, `crypto/aes` does not,
	// c'est la vie.
	if r, ok := cipher.(resetable); ok {
		r.Reset()
	}
}

// ForwardSecureAEAD is a forward-secure AEAD cipher as described in
// section `4.2 Forward-Secure AEAD` of the paper:
// https://eprint.iacr.org/2018/1037.pdf
// The Double Ratchet: Security Notions, Proofs,
// and Modularization for the Signal Protocol
//
// "Forward-secure authenticated encryption with associated data is a
// stateful primitive between a sender A and a receiver B and can be
// considered a single-epoch variant of an SM scheme, a fact that is also
// evident from its security deﬁnition, which resembles that of SM
// schemes."
type ForwardSecureAEAD struct {
	PRG *Stream

	AEADKey *[chacha20poly1305.KeySize]byte

	KeyStorage map[uint32][]byte

	ReceiveCount uint32
	ReceiveMax   uint32

	SendCount uint32
	SendMax   uint32
}

func deriveKey(key []byte, label []byte, h hash.Hash) {
	h.Reset()
	h.Write(label)
	h.Sum(key[:0])
}

// NewFSAEAD creates a new instance of ForwardSecureAEAD
func NewFSAEAD(seed []byte, isSender bool) (*ForwardSecureAEAD, error) {
	if len(seed) != SeedSize {
		return nil, errors.New("seed length is wrong")
	}

	h, err := blake2b.New512(seed)
	if err != nil {
		return nil, err
	}

	prgKey := &[StreamKeyLength]byte{}
	deriveKey(prgKey[:], prgKeyLabel, h)

	prgIV := &[StreamIVLength]byte{}
	deriveKey(prgIV[:], prgIVLabel, h)

	var keyStorage map[uint32][]byte
	if !isSender {
		keyStorage = make(map[uint32][]byte)
	}

	return &ForwardSecureAEAD{
		PRG:          NewStream(prgKey, prgIV),
		AEADKey:      nil,
		KeyStorage:   keyStorage,
		ReceiveMax:   defaultMaxReceive,
		ReceiveCount: 0,
		SendMax:      defaultMaxSend,
		SendCount:    0,
	}, nil
}

// Send implements the FSAEAD send op.
func (f *ForwardSecureAEAD) Send(message, ad []byte) ([]byte, []byte) {
	// iA ++
	f.SendCount++

	// (w, K) ← G(w)
	f.updateState()

	// h ← (iA , a)
	adPrefix := make([]byte, 4)
	binary.BigEndian.PutUint32(adPrefix, f.SendCount)

	// e ← Enc(K, h, m)
	// return (iA , e)
	aead, err := chacha20poly1305.New(f.AEADKey[:])
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, aead.NonceSize())
	ad = append(adPrefix, ad...)
	return ad, aead.Seal(nil, nonce, message, ad)
}

func (f *ForwardSecureAEAD) trySkipped(index uint32) []byte {
	k, ok := f.KeyStorage[index]
	if ok {
		delete(f.KeyStorage, index)
		return k
	}
	return nil
}

func (f *ForwardSecureAEAD) updateState() {
	stream := make([]byte, FSAEADSeedLength)
	f.PRG.KeyStream(stream)

	prgKey := &[StreamKeyLength]byte{}
	copy(prgKey[:], stream[:StreamKeyLength])
	prgIv := &[StreamIVLength]byte{}
	copy(prgIv[:], stream[StreamKeyLength:symmetricKeySize+StreamIVLength])

	f.PRG = NewStream(prgKey, prgIv)
	key := [chacha20poly1305.KeySize]byte{}
	copy(key[:], stream[symmetricKeySize+StreamIVLength:])
	f.AEADKey = &key
}

func (f *ForwardSecureAEAD) skip(count uint32) {
	if count == 0 {
		return
	}
	for f.ReceiveCount < count-1 {
		f.ReceiveCount++
		f.updateState()
		f.KeyStorage[count] = f.AEADKey[:]
	}
}

// Receive implements the FSAEAD receive op.
func (f *ForwardSecureAEAD) Receive(ciphertext, ad []byte) ([]byte, error) {
	//(i, e) ← c
	receiveCount := binary.BigEndian.Uint32(ad[:4])

	// K ← try-skipped(i)
	key := f.trySkipped(receiveCount)

	// if K = ⊥
	if key == nil {
		// skip(i)
		f.skip(receiveCount)
		// (w, K) ← G(w)
		f.updateState()
		// iB ← i
		f.ReceiveCount = receiveCount
	}

	// h ← (i, a)
	newAdPrefix := make([]byte, 4)
	binary.BigEndian.PutUint32(newAdPrefix, receiveCount)
	// m ← Dec(K, h, e)
	aead, err := chacha20poly1305.New(f.AEADKey[:])
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, aead.NonceSize())
	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// memory management methods

func (f *ForwardSecureAEAD) Stop() uint32 {
	count := f.ReceiveCount
	f.KeyStorage = make(map[uint32][]byte)
	f.PRG = nil
	f.SendCount = 0
	f.ReceiveCount = 0
	return count
}

func (f *ForwardSecureAEAD) Max(max uint32) {
	f.ReceiveMax = max
	f.SendMax = max
}
