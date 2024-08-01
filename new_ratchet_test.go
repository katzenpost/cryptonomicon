/*
Copyright (c) 2013 Adam Langley. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name Pond nor the names of its contributors may be
used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// KEM double ratchet
package ratchet

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// ratchet tests adapted from agl's pond's ratchet.

type scriptAction struct {
	// object is one of sendA, sendB or sendDelayed. The first two options
	// cause a message to be sent from one party to the other. The latter
	// causes a previously delayed message, identified by id, to be
	// delivered.
	object int
	// result is one of deliver, drop or delay. If delay, then the message
	// is stored using the value in id. This value can be repeated later
	// with a sendDelayed.
	result int
	id     int
}

const (
	sendA = iota
	sendB
	sendDelayed
	deliver
	drop
	delay
)

func testScript(t *testing.T, script []scriptAction) {
	type delayedMessage struct {
		msg       []byte
		encrypted []byte
		fromA     bool
	}

	delayedMessages := make(map[int]delayedMessage)
	a, b := pairedRatchet(t)

	for i, action := range script {
		switch action.object {
		case sendA, sendB:
			sender, receiver := a, b
			if action.object == sendB {
				sender, receiver = receiver, sender
			}

			var msg [20]byte
			_, err := rand.Reader.Read(msg[:])
			require.NoError(t, err)
			encrypted := sender.Send(msg[:])
			require.NoError(t, err)

			switch action.result {
			case deliver:
				result, err := receiver.Receive(encrypted)
				require.NoError(t, err, fmt.Sprintf("#%d: receiver returned error: %s", i, err))
				require.Equal(t, msg[:], result, fmt.Sprintf("#%d: bad message: got %x, not %x", i, result, msg[:]))
			case delay:
				_, ok := delayedMessages[action.id]
				require.False(t, ok, fmt.Sprintf("#%d: already have delayed message with id %d", i, action.id))
				delayedMessages[action.id] = delayedMessage{msg[:], encrypted, sender == a}
			case drop:
			}
		case sendDelayed:
			delayed, ok := delayedMessages[action.id]
			require.True(t, ok, fmt.Sprintf("#%d: no such delayed message id: %d", i, action.id))

			receiver := a
			if delayed.fromA {
				receiver = b
			}

			result, err := receiver.Receive(delayed.encrypted)
			require.NoError(t, err, fmt.Sprintf("#%d: receiver returned error: %s", i, err))
			require.Equal(t, delayed.msg, result, fmt.Sprintf("#%d: bad message: got %x, not %x", i, result, delayed.msg))
		}

		a = reinitRatchet(t, a)
		b = reinitRatchet(t, b)
	}
}

func Test_RatchetBackAndForth(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
	})
}

func Test_RatchetReorderAfterDHRatchet(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, deliver, -1},
		{sendA, delay, 0},
		{sendB, deliver, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
		{sendDelayed, deliver, 0},
	})
}

func Test_RatchetDroppedMessages(t *testing.T) {
	testScript(t, []scriptAction{
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, drop, -1},
		{sendA, deliver, -1},
		{sendB, deliver, -1},
	})
}

func Test_RatchetReordering(t *testing.T) {

	script := []scriptAction{}
	script = append(script, scriptAction{sendA, deliver, -1})
	for i := 0; i < maxMissingMessages; i++ {
		script = append(script, scriptAction{sendA, delay, i})
	}
	for i := maxMissingMessages; i >= 0; i-- {
		script = append(script, scriptAction{sendA, deliver, i})
	}

	testScript(t, script)
}
