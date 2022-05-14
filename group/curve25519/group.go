// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package curve25519 implements a prime-order group over Curve25519 with hash-to-curve.
package curve25519

import (
	"math/big"

	"filippo.io/edwards25519"

	ed "github.com/bytemare/crypto/group/edwards25519"
	"github.com/bytemare/crypto/group/internal"
)

const (
	// H2C represents the hash-to-curve string identifier.
	H2C = "curve25519_XMD:SHA-512_ELL2_RO_"

	// E2C represents the encode-to-curve string identifier.
	E2C = "curve25519_XMD:SHA-512_ELL2_NU_"
)

const (
	// orderPrime represents curve25519's subgroup (prime) order
	// q = 2^252 + 27742317777372353535851937790883648493
	// = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
	// cofactor h = 8
	orderPrime = "7237005577332262213973186563042994240857116359379907606001950938285454250989"
)

var (
	groupOrder, _ = new(big.Int).SetString(orderPrime, 10)
)

// Group represents the Curve25519 group. It exposes a prime-order group API with hash-to-curve operations.
type Group struct{}

func New() internal.Group {
	return Group{}
}

// NewScalar returns a new, empty, scalar.
func (g Group) NewScalar() internal.Scalar {
	return newScalar()
}

// ElementLength returns the byte size of an encoded element.
func (g Group) ElementLength() uint {
	return canonicalEncodingLength
}

// NewElement returns the identity point (point at infinity).
func (g Group) NewElement() internal.Element {
	return newPoint()
}

// Identity returns the group's identity element.
func (g Group) Identity() internal.Element {
	return newPoint()
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the group.
func (g Group) HashToGroup(input, dst []byte) internal.Element {
	return &Element{ed.HashToEdwards25519(input, dst)}
}

// EncodeToGroup allows arbitrary input to be mapped non-uniformly to points in the Group.
func (g Group) EncodeToGroup(input, dst []byte) internal.Element {
	return &Element{ed.EncodeToEdwards25519(input, dst)}
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (g Group) HashToScalar(input, dst []byte) internal.Scalar {
	return &Scalar{ed.HashToEdwards25519Field(input, dst)}
}

// Base returns the group's base point a.k.a. canonical generator.
func (g Group) Base() internal.Element {
	return &Element{edwards25519.NewGeneratorPoint()}
}

// MultBytes allows []byte encodings of a scalar and an element of the group to be multiplied.
func (g Group) MultBytes(s, e []byte) (internal.Element, error) {
	sc, err := g.NewScalar().Decode(s)
	if err != nil {
		return nil, err
	}

	el, err := g.NewElement().Decode(e)
	if err != nil {
		return nil, err
	}

	return el.Mult(sc), nil
}

func reverse(b []byte) []byte {
	l := len(b) - 1
	for i := 0; i < len(b)/2; i++ {
		b[i], b[l-i] = b[l-i], b[i]
	}

	return b
}
