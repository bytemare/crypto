// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"testing"

	ristretto2 "github.com/bytemare/crypto/internal/ristretto"
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

func TestRistrettoScalar(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ristretto2.Group{}.NewScalar().Random()
			if len(s.Encode()) != 32 {
				t.Fatalf("invalid random scalar length. Expected %d, got %d", 32, len(s.Encode()))
			}

			// Grab the bytes of the encoding
			encoding, err := hex.DecodeString(tt.scalar)
			if err != nil {
				t.Fatalf("#%s: bad hex encoding in test vector: %v", tt.name, err)
			}

			s = ristretto2.Group{}.NewScalar()
			err = s.Decode(encoding)

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

				if len(s.Encode()) != 32 {
					t.Fatalf(
						"invalid random scalar length. Expected %d, got %d",
						32,
						len(s.Encode()),
					)
				}

				cpy := s.Copy()
				cpy = cpy.Invert()
				if bytes.Equal(cpy.Encode(), s.Encode()) {
					t.Fatal("scalar inversion resulted in same scalar")
				}
			}
		})
	}
}

func TestRistrettoElement(t *testing.T) {
	// Test if the element in the test is the base point
	bp := ristretto2.Group{}.NewElement().(*ristretto2.Element).Base()

	// Grab the bytes of the encoding
	encoding, err := hex.DecodeString(tests[0].element)
	if err != nil {
		t.Fatalf("%s: bad hex encoding in test vector: %v", tests[0].name, err)
	}

	if !bytes.Equal(bp.Encode(), encoding) {
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
			e := ristretto2.Group{}.NewElement()
			err = e.Decode(encoding)

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
				if !bytes.Equal(encoding, e.Encode()) {
					t.Fatalf("%s : Decoding and encoding doesn't return the same bytes", tt.name)
				}
			}
		})
	}
}
