// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// KEM double ratchet
package ratchet

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"

	"gitlab.com/yawning/bsaes.git"

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
	cipher.Stream
}

// NewStream returns a new Stream implementing the Sphinx Stream Cipher with
// the provided key and IV.
func NewStream(key *[StreamKeyLength]byte, iv *[StreamIVLength]byte) *Stream {
	// bsaes is smart enough to detect if the Go runtime and the CPU support
	// AES-NI and PCLMULQDQ and call `crypto/aes`.
	//
	// TODO: The AES-NI `crypto/aes` CTR mode implementation is horrid and
	// massively underperforms so eventually bsaes should include assembly.
	blk, err := bsaes.NewCipher(key[:])
	if err != nil {
		// Not covered by unit tests because this indicates a bug in bsaes.
		panic("crypto/NewStream: failed to create AES instance: " + err.Error())
	}
	return &Stream{cipher.NewCTR(blk, iv[:])}
}

// KeyStream fills the buffer dst with key stream output.
func (s *Stream) KeyStream(dst []byte) {
	// TODO: Add a fast path for implementations that support it, to
	// shave off the memset and XOR.
	util.ExplicitBzero(dst)
	s.XORKeyStream(dst, dst)
}

// Reset clears the Stream instance such that no sensitive data is left in
// memory.
func (s *Stream) Reset() {
	// bsaes's ctrAble implementation exposes this, `crypto/aes` does not,
	// c'est la vie.
	if r, ok := s.Stream.(resetable); ok {
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
	prg  *Stream
	aead cipher.AEAD

	keyStorage map[uint32][]byte

	receiveCount uint32
	receiveMax   uint32

	sendCount uint32
	sendMax   uint32
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

	aeadKey := make([]byte, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		return nil, err
	}

	keyStorage := make(map[uint32][]byte)
	if !isSender {
		keyStorage[0] = aeadKey
	}

	return &ForwardSecureAEAD{
		prg:          NewStream(prgKey, prgIV),
		aead:         aead,
		keyStorage:   keyStorage,
		receiveMax:   defaultMaxReceive,
		receiveCount: 0,
		sendMax:      defaultMaxSend,
		sendCount:    0,
	}, nil
}

// Send implements the FSAEAD send op.
func (f *ForwardSecureAEAD) Send(message, ad []byte) (uint32, []byte) {
	f.sendCount++
	fmt.Println("Send updateState")
	f.updateState(true)

	nonce := make([]byte, f.aead.NonceSize())

	adPrefix := make([]byte, 4)
	binary.BigEndian.PutUint32(adPrefix, f.sendCount)

	return f.sendCount, f.aead.Seal(nil, nonce, message, append(adPrefix, ad...))
}

func (f *ForwardSecureAEAD) trySkipped(index uint32) []byte {
	fmt.Println("trySkipped")
	k, ok := f.keyStorage[index]
	if ok {
		fmt.Println("trySkipped found")
		delete(f.keyStorage, index)
		return k
	}
	return nil
}

func (f *ForwardSecureAEAD) updateState(isSender bool) []byte {
	stream := make([]byte, FSAEADSeedLength)
	f.prg.KeyStream(stream)

	prgKey := &[StreamKeyLength]byte{}
	copy(prgKey[:], stream[:StreamKeyLength])
	prgIv := &[StreamIVLength]byte{}
	copy(prgIv[:], stream[StreamKeyLength:symmetricKeySize+StreamIVLength])

	f.prg = NewStream(prgKey, prgIv)

	aeadKey := make([]byte, chacha20poly1305.KeySize)
	copy(aeadKey, stream[symmetricKeySize+StreamIVLength:])

	var err error
	f.aead, err = chacha20poly1305.New(aeadKey)
	if err != nil {
		panic(err)
	}
	return aeadKey
}

func (f *ForwardSecureAEAD) skip(count uint32) {
	for f.receiveCount < count-1 {
		f.receiveCount++
		aeadKey := f.updateState(false)
		f.keyStorage[count] = aeadKey
	}
}

// Receive implements the FSAEAD receive op.
func (f *ForwardSecureAEAD) Receive(ciphertext, ad []byte, receiveCount uint32) ([]byte, uint32, error) {
	key := f.trySkipped(receiveCount)
	if key == nil {
		f.skip(receiveCount)
		f.updateState(false)
		f.receiveCount = receiveCount
	}

	nonce := make([]byte, f.aead.NonceSize())
	newAdPrefix := make([]byte, 4)
	binary.BigEndian.PutUint32(newAdPrefix, receiveCount)
	plaintext, err := f.aead.Open(nil, nonce, ciphertext, append(newAdPrefix, ad...))
	if err != nil {
		return nil, 0, err
	}
	return plaintext, receiveCount, nil
}

// memory management methods

func (f *ForwardSecureAEAD) Stop() uint32 {
	count := f.receiveCount
	f.keyStorage = make(map[uint32][]byte)
	f.prg = nil
	f.aead = nil
	f.sendCount = 0
	f.receiveCount = 0
	return count
}

func (f *ForwardSecureAEAD) Max(max uint32) {
	f.receiveMax = max
	f.sendMax = max
}
