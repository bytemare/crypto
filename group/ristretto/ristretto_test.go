// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ristretto

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/bytemare/crypto/internal"
)

const (
	goodScalar = "243170e83a77812893c234314116e1c007671adfe23325011e3827c1b2ff8d0a"
	basePoint  = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"

	testApp     = "testRistretto255"
	testVersion = "0.0"
)

type testGroup struct {
	name            string
	hashID          crypto.Hash
	app             string
	version         string
	scalar, element string // hex encoding of a scalar and element
	scal, elem      bool   // says whether the scalar or element is supposed to be valid
}

const h2cInput = "H2C Input"

// todo: adapt to different hashing algorithms
var tests = []testGroup{
	{
		name:    "Valid element (base point), valid scalar",
		hashID:  crypto.SHA512,
		app:     testApp,
		version: testVersion,
		scalar:  goodScalar,
		element: basePoint,
		scal:    true,
		elem:    true,
	},
	{
		name:    "Valid element (base point), wrong scalar (size)",
		hashID:  crypto.SHA512,
		app:     testApp,
		version: testVersion,
		scalar:  "243170e83a77812893c234314116e1c007671adfe23325011e3827c1b2ff8d",
		element: basePoint,
		scal:    false,
		elem:    true,
	},
	{
		name:    "Valid element (base point), wrong scalar (encoding)",
		hashID:  crypto.SHA512,
		app:     testApp,
		version: testVersion,
		scalar:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		element: basePoint,
		scal:    false,
		elem:    true,
	},
	{
		name:    "Valid scalar, bad element",
		hashID:  crypto.SHA512,
		app:     testApp,
		version: testVersion,
		scalar:  goodScalar,
		element: "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
		scal:    true,
		elem:    false,
	},
	{
		name:    "Nil scalar, bad element",
		hashID:  crypto.SHA512,
		app:     testApp,
		version: testVersion,
		scalar:  "",
		element: "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
		scal:    false,
		elem:    false,
	},
	{
		name:    "Nil scalar, nil element",
		hashID:  crypto.SHA512,
		app:     testApp,
		version: testVersion,
		scalar:  "",
		element: "",
		scal:    false,
		elem:    false,
	},
}

func TestNilScalar(t *testing.T) {
	_, err := Group{}.NewScalar().Decode(nil)
	if err == nil {
		t.Fatal("expected error on nil input")
	}
}

func TestScalar(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Group{}.NewScalar().Random()
			if len(s.Bytes()) != canonicalEncodingLength {
				t.Fatalf("invalid random scalar length. Expected %d, got %d", canonicalEncodingLength, len(s.Bytes()))
			}

			// Grab the bytes of the encoding
			encoding, err := hex.DecodeString(tt.scalar)
			if err != nil {
				t.Fatalf("#%s: bad hex encoding in test vector: %v", tt.name, err)
			}

			s, err = Group{}.NewScalar().Decode(encoding)

			switch tt.scal {
			case false:
				if err == nil {
					t.Fatalf("expected error for %s", tt.name)
				}

				if s != nil {
					t.Fatalf("unexpected nil scalar for %s", tt.name)
				}
			case true:
				if err != nil {
					t.Fatalf("%s : unexpected error, got %v", tt.name, err)
				}

				if s == nil {
					t.Fatal("scalar is nil, should not happen")
				}

				if len(s.Bytes()) != canonicalEncodingLength {
					t.Fatalf("invalid random scalar length. Expected %d, got %d", canonicalEncodingLength, len(s.Bytes()))
				}

				cpy, _ := Group{}.NewScalar().Decode(s.Bytes())
				cpy = cpy.Invert()
				if bytes.Equal(cpy.Bytes(), s.Bytes()) {
					t.Fatal("scalar inversion resulted in same scalar")
				}
			}
		})
	}
}

func TestNilElement(t *testing.T) {
	// Test if the element in the test is the base point
	_, err := Group{}.NewElement().Decode(nil)
	if err == nil {
		t.Fatal("expected error on nil input")
	}
}

func TestElement(t *testing.T) {
	// Test if the element in the test is the base point
	bp := Group{}.NewElement().(*Point).Base()

	// Grab the bytes of the encoding
	encoding, err := hex.DecodeString(tests[0].element)
	if err != nil {
		t.Fatalf("%s: bad hex encoding in test vector: %v", tests[0].name, err)
	}

	if !bytes.Equal(bp.Bytes(), encoding) {
		t.Fatalf("%s: element doesn't decode to basepoint", tests[0].name)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Grab the bytes of the encoding
			encoding, err := hex.DecodeString(tt.element)
			if err != nil {
				t.Fatalf("%s: bad hex encoding in test vector: %v", tt.name, err)
			}

			// Test decoding
			e, err := Group{}.NewElement().Decode(encoding)

			switch tt.elem {
			case false:
				if err == nil {
					t.Fatalf("expected error for %s", tt.name)
				}

				if e != nil {
					t.Fatalf("%s : element is not nil but should have failed on decoding", tt.name)
				}

			case true:
				if err != nil {
					t.Fatalf("%s : unexpected error, got %v", tt.name, err)
				}

				if e == nil {
					t.Fatalf("%s : element is nil but should not have failed on decoding", tt.name)
				}

				// Test encoding
				if !bytes.Equal(encoding, e.Bytes()) {
					t.Fatalf("%s : Decoding and encoding doesn't return the same bytes", tt.name)
				}
			}
		})
	}
}

func TestMultiplication(t *testing.T) {
	if hasPanic, _ := internal.ExpectPanic(nil, func() {
		_ = Group{}.NewElement().Mult(nil)
	}); !hasPanic {
		t.Fatal("expected panic on multiplying with nil scalar")
	}

	bp := Group{}.NewElement().(*Point).Base()
	rs := Group{}.NewScalar().Random()

	//
	m1 := bp.Mult(rs)

	//
	m2, err := Group{}.MultBytes(rs.Bytes(), Group{}.NewElement().(*Point).Base().Bytes())
	if err != nil {
		t.Fatalf("unexpected err ; %v", err)
	}

	if !bytes.Equal(m1.Bytes(), m2.Bytes()) {
		t.Fatalf("expected equality in multiplication")
	}

	// Blind and unblind
	bp = Group{}.NewElement().(*Point).Base()
	blinded := bp.Mult(rs)

	if bytes.Equal(blinded.Bytes(), Group{}.NewElement().(*Point).Base().Bytes()) {
		t.Fatalf("failed multiplication : didn't change")
	}

	if blinded.IsIdentity() {
		t.Fatalf("failed multiplication : is identity")
	}

	// unblind
	if hasPanic, _ := internal.ExpectPanic(nil, func() {
		_ = bp.InvertMult(nil)
	}); !hasPanic {
		t.Fatal("expected panic when invertmult with nil scalar")
	}

	unblinded := blinded.InvertMult(rs)
	if !bytes.Equal(unblinded.Bytes(), Group{}.Base().Bytes()) {
		t.Fatalf("failed multiplication : unblinding didn't revert")
	}

	// Multiply from byte values
	element := Group{}.NewElement().(*Point).Base()
	scalar := Group{}.NewScalar().Random()

	mult := Group{}.NewElement().(*Point).Base().Mult(scalar)

	bm, err := Group{}.MultBytes(scalar.Bytes(), element.Bytes())
	if err != nil {
		t.Fatalf("MultBytes errored for []bytes multiplication")
	}

	if !bytes.Equal(mult.Bytes(), bm.Bytes()) {
		t.Fatalf("MultBytes failed. expected %x, got %x", mult.Bytes(), bm.Bytes())
	}

	// Multiply with invalid values
	r := Group{}
	if _, err := r.MultBytes(nil, nil); err == nil {
		t.Fatal("expected error for nil scalar in MultBytes")
	}

	if _, err := r.MultBytes(scalar.Bytes(), nil); err == nil {
		t.Fatal("expected error for nil scalar in MultBytes")
	}
}

func TestPointArithmetic(t *testing.T) {
	input := []byte(h2cInput)

	// Test Addition and Subtraction
	p := Group{}.Base()
	c := p.Copy()
	if hasPanic, _ := internal.ExpectPanic(nil, func() {
		p.Add(nil)
	}); !hasPanic {
		t.Fatal("expected panic")
	}
	a := p.Add(p)
	if hasPanic, _ := internal.ExpectPanic(nil, func() {
		p.Sub(nil)
	}); !hasPanic {
		t.Fatal("expected panic")
	}
	r := a.Sub(c)
	if !bytes.Equal(r.Bytes(), c.Bytes()) {
		t.Fatal("not equal")
	}

	// Test Multiplication and inversion
	p = Group{}.Base()
	s := Group{}.HashToScalar(input, []byte("test"))
	penc := p.Bytes()
	senc := s.Bytes()
	m := p.Mult(s)
	e, err := Group{}.MultBytes(senc, penc)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(m.Bytes(), e.Bytes()) {
		t.Fatal("not equal")
	}
	if hasPanic, _ := internal.ExpectPanic(nil, func() {
		p.InvertMult(nil)
	}); !hasPanic {
		t.Fatal("expected panic")
	}
	i := m.InvertMult(s)
	if !bytes.Equal(i.Bytes(), p.Bytes()) {
		t.Fatal("not equal")
	}

	// Test identity
	p = p.Sub(p)
	if !p.IsIdentity() {
		t.Fatal("expected assertion to be true")
	}
	if !bytes.Equal(p.Bytes(), Group{}.Identity().Bytes()) {
		t.Fatal("not equal")
	}
}

func TestScalarArithmetic(t *testing.T) {
	// Test Addition and Substraction
	s := Group{}.NewScalar().Random()
	if !bytes.Equal(s.Add(nil).Bytes(), s.Bytes()) {
		t.Fatal("not equal")
	}
	a := s.Add(s)
	if !bytes.Equal(a.Sub(nil).Bytes(), a.Bytes()) {
		t.Fatal("not equal")
	}
	r := a.Sub(s)
	if !bytes.Equal(r.Bytes(), s.Bytes()) {
		t.Fatal("not equal")
	}

	// Test Multiplication and inversion
	s = Group{}.NewScalar().Random()
	m := s.Mult(s)
	i := m.Mult(s.Invert())
	if !bytes.Equal(i.Bytes(), s.Bytes()) {
		t.Fatal("not equal")
	}
}
