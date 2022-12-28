// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"testing"

	"github.com/bytemare/crypto"
)

// a testGroup references some components of a Group.
type testGroup struct {
	name          string
	h2c           string
	e2c           string
	basePoint     string
	elementLength int
	scalarLength  int
	id            crypto.Group
}

func testGroups() []*testGroup {
	return []*testGroup{
		{"Ristretto255", "ristretto255_XMD:SHA-512_R255MAP_RO_", "ristretto255_XMD:SHA-512_R255MAP_RO_", "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76", 32, 32, 1},
		{"P256", "P256_XMD:SHA-256_SSWU_RO_", "P256_XMD:SHA-256_SSWU_NU_", "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 33, 32, 3},
		{"P384", "P384_XMD:SHA-384_SSWU_RO_", "P384_XMD:SHA-384_SSWU_NU_", "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 49, 48, 4},
		{"P521", "P521_XMD:SHA-512_SSWU_RO_", "P521_XMD:SHA-512_SSWU_NU_", "0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 67, 66, 5},
	}
}

func testAll(t *testing.T, f func(*testing.T, *testGroup)) {
	for _, test := range testGroups() {
		t.Run(test.name, func(t *testing.T) {
			f(t, test)
		})
	}
}

var (
	errNoPanic        = errors.New("no panic")
	errNoPanicMessage = errors.New("panic but no message")
)

func hasPanic(f func()) (has bool, err error) {
	defer func() {
		var report any
		if report = recover(); report != nil {
			has = true
			err = fmt.Errorf("%v", report)
		}
	}()

	f()

	return has, err
}

// testPanic executes the function f with the expectation to recover from a panic. If no panic occurred or if the
// panic message is not the one expected, ExpectPanic returns an error.
func testPanic(s string, expectedError error, f func()) error {
	hasPanic, err := hasPanic(f)

	// if there was no panic
	if !hasPanic {
		return errNoPanic
	}

	// panic, and we don't expect a particular message
	if expectedError == nil {
		return nil
	}

	// panic, but the panic value is empty
	if err == nil {
		return errNoPanicMessage
	}

	// panic, but the panic value is not what we expected
	if err.Error() != expectedError.Error() {
		return fmt.Errorf("expected panic on %s with message %q, got %q", s, expectedError, err)
	}

	return nil
}

type serde interface {
	Encode() []byte
	Decode(data []byte) error
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

func testEncoding(t *testing.T, thing1, thing2 serde) {
	encoded := thing1.Encode()
	marshalled, _ := thing1.MarshalBinary()

	if !bytes.Equal(encoded, marshalled) {
		t.Fatalf("Encode() and MarshalBinary() are expected to have the same output.\twant: %v\tgot : %v", encoded, marshalled)
	}

	if err := thing2.Decode(nil); err == nil {
		t.Fatal("expected error on Decode() with nil input")
	}

	if err := thing2.Decode(encoded); err != nil {
		t.Fatalf("Decode() failed on a valid encoding: %v", err)
	}

	if err := thing2.UnmarshalBinary(encoded); err != nil {
		t.Fatalf("UnmarshalBinary() failed on a valid encoding: %v", err)
	}
}

func TestEncoding(t *testing.T) {
	testAll(t, func(t *testing.T, group *testGroup) {
		scalar := group.id.NewScalar().Random()
		testEncoding(t, scalar, group.id.NewScalar())

		scalar = group.id.NewScalar().Random()
		element := group.id.Base().Multiply(scalar)
		testEncoding(t, element, group.id.NewElement())
	})
}
