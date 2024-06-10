// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"bytes"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/bytemare/crypto"
)

var (
	errNoPanic        = errors.New("no panic")
	errNoPanicMessage = errors.New("panic but no message")
	errZeroLenDST     = errors.New("zero-length DST")
	errWrapGroup      = "%s: %w"
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

func decodeScalar(t *testing.T, g crypto.Group, input string) *crypto.Scalar {
	b, err := hex.DecodeString(input)
	if err != nil {
		t.Error(err)
	}

	s := g.NewScalar()
	if err := s.Decode(b); err != nil {
		t.Error(err)
	}

	return s
}

func decodeElement(t *testing.T, g crypto.Group, input string) *crypto.Element {
	b, err := hex.DecodeString(input)
	if err != nil {
		t.Error(err)
	}

	e := g.NewElement()
	if err := e.Decode(b); err != nil {
		t.Error(err)
	}

	return e
}

type serde interface {
	Encode() []byte
	Decode(data []byte) error
	Hex() string
	DecodeHex(h string) error
	encoding.BinaryMarshaler
	encoding.BinaryUnmarshaler
}

func testEncoding(t *testing.T, thing1, thing2 serde) {
	// empty string
	if err := thing2.DecodeHex(""); err == nil {
		t.Fatal("expected error on empty string")
	}

	encoded := thing1.Encode()
	marshalled, _ := thing1.MarshalBinary()
	hexed := thing1.Hex()

	if !bytes.Equal(encoded, marshalled) {
		t.Fatalf("Encode() and MarshalBinary() are expected to have the same output."+
			"\twant: %v\tgot : %v", encoded, marshalled)
	}

	if hex.EncodeToString(encoded) != hexed {
		t.Fatalf("Failed hex encoding, want %q, got %q", hex.EncodeToString(encoded), hexed)
	}

	if err := thing2.Decode(nil); err == nil {
		t.Fatal("expected error on Decode() with nil input")
	}

	if err := thing2.Decode(encoded); err != nil {
		t.Fatalf("Decode() failed on a valid encoding: %v. Value: %v", err, hex.EncodeToString(encoded))
	}

	if err := thing2.UnmarshalBinary(encoded); err != nil {
		t.Fatalf("UnmarshalBinary() failed on a valid encoding: %v", err)
	}

	if err := thing2.DecodeHex(hexed); err != nil {
		t.Fatalf("DecodeHex() failed on valid hex encoding: %v", err)
	}
}

func TestEncoding(t *testing.T) {
	testAll(t, func(group *testGroup) {
		g := group.group
		scalar := g.NewScalar().Random()
		testEncoding(t, scalar, g.NewScalar())

		scalar = g.NewScalar().Random()
		element := g.Base().Multiply(scalar)
		testEncoding(t, element, g.NewElement())
	})
}

func testDecodingHexFails(t *testing.T, thing1, thing2 serde) {
	// empty string
	if err := thing2.DecodeHex(""); err == nil {
		t.Fatal("expected error on empty string")
	}

	// malformed string
	hexed := thing1.Hex()
	malformed := []rune(hexed)
	malformed[0] = []rune("_")[0]

	if err := thing2.DecodeHex(string(malformed)); err == nil {
		t.Fatal("expected error on malformed string")
	} else {
		t.Log(err)
	}
}

func TestEncoding_Hex_Fails(t *testing.T) {
	testAll(t, func(group *testGroup) {
		g := group.group
		scalar := g.NewScalar().Random()
		testEncoding(t, scalar, g.NewScalar())

		scalar = g.NewScalar().Random()
		element := g.Base().Multiply(scalar)
		testEncoding(t, element, g.NewElement())

		// Hex fails
		testDecodingHexFails(t, scalar, g.NewScalar())
		testDecodingHexFails(t, element, g.NewElement())

		// Doesn't yield the same decoded result
		scalar = g.NewScalar().Random()
		s := g.NewScalar()
		if err := s.DecodeHex(scalar.Hex()); err != nil {
			t.Fatalf("unexpected error on valid encoding: %s", err)
		}

		if s.Equal(scalar) != 1 {
			t.Fatal(errExpectedEquality)
		}

		element = g.Base().Multiply(scalar)
		e := g.NewElement()
		if err := e.DecodeHex(element.Hex()); err != nil {
			t.Fatalf("unexpected error on valid encoding: %s", err)
		}

		if e.Equal(element) != 1 {
			t.Fatal(errExpectedEquality)
		}
	})
}
