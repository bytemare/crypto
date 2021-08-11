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

	"github.com/stretchr/testify/assert"
)

const (
	goodScalar = "243170e83a77812893c234314116e1c007671adfe23325011e3827c1b2ff8d0a"
	basePoint  = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"

	testApp         = "testRistretto255"
	testVersion     = "0.0"
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
	_, err := Ristretto255Sha512{}.NewScalar().Decode(nil)
	if err == nil {
		t.Fatal("expected error on nil input")
	}
}

func TestScalar(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Ristretto255Sha512{}.NewScalar().Random()
			if len(s.Bytes()) != canonicalEncodingLength {
				t.Fatalf("invalid random scalar length. Expected %d, got %d", canonicalEncodingLength, len(s.Bytes()))
			}

			// Grab the bytes of the encoding
			encoding, err := hex.DecodeString(tt.scalar)
			if err != nil {
				t.Fatalf("#%s: bad hex encoding in test vector: %v", tt.name, err)
			}

			s, err = Ristretto255Sha512{}.NewScalar().Decode(encoding)

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

				cpy, _ := Ristretto255Sha512{}.NewScalar().Decode(s.Bytes())
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
	_, err := Ristretto255Sha512{}.NewElement().Decode(nil)
	if err == nil {
		t.Fatal("expected error on nil input")
	}
}

func TestElement(t *testing.T) {
	// Test if the element in the test is the base point
	bp := Ristretto255Sha512{}.NewElement().(*Point).Base()

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
			e, err := Ristretto255Sha512{}.NewElement().Decode(encoding)

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
	assert.Panics(t, func() {
		_ = Ristretto255Sha512{}.NewElement().Mult(nil)
	}, "expected panic on multiplying with nil scalar")

	bp := Ristretto255Sha512{}.NewElement().(*Point).Base()
	rs := Ristretto255Sha512{}.NewScalar().Random()

	//
	m1 := bp.Mult(rs)

	//
	m2, err := Ristretto255Sha512{}.MultBytes(rs.Bytes(), Ristretto255Sha512{}.NewElement().(*Point).Base().Bytes())
	if err != nil {
		t.Fatalf("unexpected err ; %v", err)
	}

	if !bytes.Equal(m1.Bytes(), m2.Bytes()) {
		t.Fatalf("expected equality in multiplication")
	}

	// Blind and unblind
	bp = Ristretto255Sha512{}.NewElement().(*Point).Base()
	blinded := bp.Mult(rs)

	if bytes.Equal(blinded.Bytes(), Ristretto255Sha512{}.NewElement().(*Point).Base().Bytes()) {
		t.Fatalf("failed multiplication : didn't change")
	}

	if blinded.IsIdentity() {
		t.Fatalf("failed multiplication : is identity")
	}

	// unblind
	assert.Panics(t, func() {
		_ = bp.InvertMult(nil)
	}, "expect panic when invertmult with nil scalar")

	unblinded := blinded.InvertMult(rs)

	if !bytes.Equal(unblinded.Bytes(), Ristretto255Sha512{}.Base().Bytes()) {
		t.Fatalf("failed multiplication : unblinding didn't revert")
	}

	// Multiply from byte values
	element := Ristretto255Sha512{}.NewElement().(*Point).Base()
	scalar := Ristretto255Sha512{}.NewScalar().Random()

	mult := Ristretto255Sha512{}.NewElement().(*Point).Base().Mult(scalar)

	bm, err := Ristretto255Sha512{}.MultBytes(scalar.Bytes(), element.Bytes())
	if err != nil {
		t.Fatalf("MultBytes errored for []bytes multiplication")
	}

	if !bytes.Equal(mult.Bytes(), bm.Bytes()) {
		t.Fatalf("MultBytes failed. expected %x, got %x", mult.Bytes(), bm.Bytes())
	}

	// Multiply with invalid values
	r := Ristretto255Sha512{}
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
	p := Ristretto255Sha512{}.Base()
	c := p.Copy()
	assert.Panics(t, func() { p.Add(nil) })
	a := p.Add(p)
	assert.Panics(t, func() { a.Sub(nil) })
	r := a.Sub(c)
	assert.Equal(t, r.Bytes(), c.Bytes())

	// Test Multiplication and inversion
	p = Ristretto255Sha512{}.Base()
	s := Ristretto255Sha512{}.HashToScalar(input, []byte("test"))
	penc := p.Bytes()
	senc := s.Bytes()
	m := p.Mult(s)
	e, err := Ristretto255Sha512{}.MultBytes(senc, penc)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, m.Bytes(), e.Bytes())
	assert.Panics(t, func() { m.InvertMult(nil) })
	i := m.InvertMult(s)
	assert.Equal(t, i.Bytes(), p.Bytes())

	// Test identity
	p = p.Sub(p)
	assert.True(t, p.IsIdentity())
	assert.Equal(t, p.Bytes(), Ristretto255Sha512{}.Identity().Bytes())
}

func TestScalarArithmetic(t *testing.T) {
	// Test Addition and Substraction
	s := Ristretto255Sha512{}.NewScalar().Random()
	assert.Equal(t, s.Add(nil).Bytes(), s.Bytes())
	a := s.Add(s)
	assert.Equal(t, a.Sub(nil).Bytes(), a.Bytes())
	r := a.Sub(s)
	assert.Equal(t, r.Bytes(), s.Bytes())

	// Test Multiplication and inversion
	s = Ristretto255Sha512{}.NewScalar().Random()
	m := s.Mult(s)
	i := m.Mult(s.Invert())
	assert.Equal(t, i.Bytes(), s.Bytes())
}
