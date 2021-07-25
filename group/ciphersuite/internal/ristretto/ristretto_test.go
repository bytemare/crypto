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
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/gtank/ristretto255"

	"github.com/bytemare/cryptotools/group/ciphersuite/internal/ristretto/h2r"

	"github.com/stretchr/testify/assert"

	"github.com/bytemare/cryptotools/hash"
)

const (
	dstMaxLength = 255

	goodScalar = "243170e83a77812893c234314116e1c007671adfe23325011e3827c1b2ff8d0a"
	basePoint  = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"

	testApp         = "testRistretto255"
	testVersion     = "0.0"
	testCiphersuite = "cipherSuite"
)

type testGroup struct {
	name            string
	hashID          hash.Hashing
	app             string
	version         string
	scalar, element string // hex encoding of a scalar and element
	scal, elem      bool   // says whether the scalar or element is supposed to be valid
}

var (
	hashAlgs = []hash.Identifier{hash.SHA256, hash.SHA512, hash.SHA3_256, hash.SHA3_512, hash.SHAKE128, hash.SHAKE256}
	testDst  = "TestApp-V00-CS123"
	h2cInput = "H2C Input"
)

type h2c struct {
	hash.Identifier
	hash  string
	h2cID string
}

var h2cR255 = []*h2c{
	{
		Identifier: hash.SHA256,
		hash:       "f890112b9ac4945a4db5e9dcaac23603e6201b58387017f0b858f7b76ea02e4e",
		h2cID:      "ristretto255_XMD:SHA256_R255MAP_RO_",
	},
	{
		Identifier: hash.SHA512,
		hash:       "86e7ca3545247c5b66acbce63e858e4142bbafb3647fe625e5d5e8ee0e624624",
		h2cID:      "ristretto255_XMD:SHA512_R255MAP_RO_",
	},
	{
		Identifier: hash.SHA3_256,
		hash:       "32c55e0b6167dc01288f84ab864103aef0fb05151409439db9e49bd760e50953",
		h2cID:      "ristretto255_XMD:SHA3-256_R255MAP_RO_",
	},
	{
		Identifier: hash.SHA3_512,
		hash:       "6c98f379e15cfbd28641137d9cd44f21eed6e66a967d6e66a97863af624ad437",
		h2cID:      "ristretto255_XMD:SHA3-512_R255MAP_RO_",
	},
	{
		Identifier: hash.SHAKE128,
		hash:       "840a80e25d220ffec374a45f42ca2fa9fd882279dfd97e5cf9bef8f293469130",
		h2cID:      "ristretto255_XOF:SHAKE128_R255MAP_RO_",
	},
	{
		Identifier: hash.SHAKE256,
		hash:       "fa39869a29dbefebbca9e4635d8f41cc96a504a06174baf013a3c341d865481c",
		h2cID:      "ristretto255_XOF:SHAKE256_R255MAP_RO_",
	},
}

// todo: adapt to different hashing algorithms
var tests = []testGroup{
	{
		name:    "Valid element (base point), valid scalar",
		hashID:  hash.SHA3_512,
		app:     testApp,
		version: testVersion,
		scalar:  goodScalar,
		element: basePoint,
		scal:    true,
		elem:    true,
	},
	{
		name:    "Valid element (base point), wrong scalar (size)",
		hashID:  hash.SHA3_512,
		app:     testApp,
		version: testVersion,
		scalar:  "243170e83a77812893c234314116e1c007671adfe23325011e3827c1b2ff8d",
		element: basePoint,
		scal:    false,
		elem:    true,
	},
	{
		name:    "Valid element (base point), wrong scalar (encoding)",
		hashID:  hash.SHA3_512,
		app:     testApp,
		version: testVersion,
		scalar:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		element: basePoint,
		scal:    false,
		elem:    true,
	},
	{
		name:    "Valid scalar, bad element",
		hashID:  hash.SHA3_512,
		app:     testApp,
		version: testVersion,
		scalar:  goodScalar,
		element: "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
		scal:    true,
		elem:    false,
	},
	{
		name:    "Nil scalar, bad element",
		hashID:  hash.SHA3_512,
		app:     testApp,
		version: testVersion,
		scalar:  "",
		element: "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08",
		scal:    false,
		elem:    false,
	},
	{
		name:    "Nil scalar, nil element",
		hashID:  hash.SHA3_512,
		app:     testApp,
		version: testVersion,
		scalar:  "",
		element: "",
		scal:    false,
		elem:    false,
	},
}

func dst(app, version, h2c string, identifier byte) []byte {
	return []byte(fmt.Sprintf("%s-V%s-CS%v-%s", app, version, identifier, h2c))
}

func TestNilScalar(t *testing.T) {
	_, err := NewScalar().Decode(nil)
	if err == nil {
		t.Fatal("expected error on nil input")
	}
}

func TestScalar(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewScalar().Random()
			if len(s.Bytes()) != canonicalEncodingLength {
				t.Fatalf("invalid random scalar length. Expected %d, got %d", canonicalEncodingLength, len(s.Bytes()))
			}

			// Grab the bytes of the encoding
			encoding, err := hex.DecodeString(tt.scalar)
			if err != nil {
				t.Fatalf("#%s: bad hex encoding in test vector: %v", tt.name, err)
			}

			s, err = NewScalar().Decode(encoding)

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

				cpy, _ := NewScalar().Decode(s.Bytes())
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
	_, err := NewElement().Decode(nil)
	if err == nil {
		t.Fatal("expected error on nil input")
	}
}

func TestElement(t *testing.T) {
	// Test if the element in the test is the base point
	bp := NewElement().(*Element).Base()

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
			e, err := NewElement().Decode(encoding)

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

func hash2group(input, dst []byte, id hash.Identifier) *Element {
	h := h2r.New(id)
	uniform := h.ExpandMessage(input, dst, ristrettoInputLength)

	return &Element{
		element: ristretto255.NewElement().FromUniformBytes(uniform),
	}
}

func TestHashToCurveSucceed(t *testing.T) {
	for _, h := range h2cR255 {
		t.Run(h.Identifier.String(), func(t *testing.T) {
			dst := dst(testApp, testVersion, testCiphersuite, 0x02)

			// Grab the bytes of the encoding
			encoding, err := hex.DecodeString(h.hash)
			if err != nil {
				t.Fatalf("%s: bad hex encoding in test vector: %v", h.Identifier, err)
			}

			m := hash2group([]byte(h2cInput), dst, h.Identifier)

			if !bytes.Equal(encoding, m.Bytes()) {
				t.Fatalf("encodings do not match. expected %v, got %v", hex.EncodeToString(encoding), hex.EncodeToString(m.Bytes()))
			}

			// Try again with very long DST
			proto := strings.Repeat("a", dstMaxLength+1)
			assert.NotPanics(t, func() {
				_ = HashToGroup([]byte(h2cInput), []byte(proto))
			}, "expected no panic with very long dst")
		})
	}
}

func TestMultiplication(t *testing.T) {
	assert.Panics(t, func() {
		_ = NewElement().Mult(nil)
	}, "expected panic on multiplying with nil scalar")

	bp := NewElement().(*Element).Base()
	rs := NewScalar().Random()

	//
	m1 := bp.Mult(rs)

	//
	m2, err := MultBytes(rs.Bytes(), NewElement().(*Element).Base().Bytes())
	if err != nil {
		t.Fatalf("unexpected err ; %v", err)
	}

	if !bytes.Equal(m1.Bytes(), m2.Bytes()) {
		t.Fatalf("expected equality in multiplication")
	}

	// Blind and unblind
	bp = NewElement().(*Element).Base()
	blinded := bp.Mult(rs)

	if bytes.Equal(blinded.Bytes(), NewElement().(*Element).Base().Bytes()) {
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

	if !bytes.Equal(unblinded.Bytes(), Base().Bytes()) {
		t.Fatalf("failed multiplication : unblinding didn't revert")
	}

	// Multiply from byte values
	element := NewElement().(*Element).Base()
	scalar := NewScalar().Random()

	mult := NewElement().(*Element).Base().Mult(scalar)

	bm, err := MultBytes(scalar.Bytes(), element.Bytes())
	if err != nil {
		t.Fatalf("MultBytes errored for []bytes multiplication")
	}

	if !bytes.Equal(mult.Bytes(), bm.Bytes()) {
		t.Fatalf("MultBytes failed. expected %x, got %x", mult.Bytes(), bm.Bytes())
	}

	// Multiply with invalid values
	if _, err := MultBytes(nil, nil); err == nil {
		t.Fatal("expected error for nil scalar in MultBytes")
	}

	if _, err := MultBytes(scalar.Bytes(), nil); err == nil {
		t.Fatal("expected error for nil scalar in MultBytes")
	}
}

func TestPointArithmetic(t *testing.T) {
	input := []byte(h2cInput)

	// Test Addition and Subtraction
	p := Base()
	c := p.Copy()
	assert.Panics(t, func() { p.Add(nil) })
	a := p.Add(p)
	assert.Panics(t, func() { a.Sub(nil) })
	r := a.Sub(c)
	assert.Equal(t, r.Bytes(), c.Bytes())

	// Test Multiplication and inversion
	p = Base()
	s := HashToScalar(input, nil)
	penc := p.Bytes()
	senc := s.Bytes()
	m := p.Mult(s)
	e, err := MultBytes(senc, penc)
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
	assert.Equal(t, p.Bytes(), Identity().Bytes())
}

func TestScalarArithmetic(t *testing.T) {
	// Test Addition and Substraction
	s := NewScalar().Random()
	assert.Equal(t, s.Add(nil).Bytes(), s.Bytes())
	a := s.Add(s)
	assert.Equal(t, a.Sub(nil).Bytes(), a.Bytes())
	r := a.Sub(s)
	assert.Equal(t, r.Bytes(), s.Bytes())

	// Test Multiplication and inversion
	s = NewScalar().Random()
	m := s.Mult(s)
	i := m.Mult(s.Invert())
	assert.Equal(t, i.Bytes(), s.Bytes())
}
