// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package edwards25519 wraps filippo.io/edwards25519 and exposes a simple prime-order group API with hash-to-curve.
package edwards25519

import (
	"math/big"

	"filippo.io/edwards25519"

	"github.com/bytemare/crypto/internal"
)

const (
	// H2C represents the hash-to-curve string identifier.
	H2C = "edwards25519_XMD:SHA-512_ELL2_RO_"

	// E2C represents the encode-to-curve string identifier.
	E2C = "edwards25519_XMD:SHA-512_ELL2_NU_"

	// orderPrime represents curve25519's subgroup (prime) order
	// = 2^252 + 27742317777372353535851937790883648493
	// = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
	// cofactor h = 8.
	orderPrime = "7237005577332262213973186563042994240857116359379907606001950938285454250989"
)

var groupOrder, _ = new(big.Int).SetString(orderPrime, 10)

// Group represents the Edwards25519 group. It exposes a prime-order group API with hash-to-curve operations.
type Group struct{}

func New() internal.Group {
	return Group{}
}

// NewScalar returns a new, empty, scalar.
func (g Group) NewScalar() internal.Scalar {
	return &Scalar{*edwards25519.NewScalar()}
}

// NewElement returns the identity point (point at infinity).
func (g Group) NewElement() internal.Element {
	return &Element{*edwards25519.NewIdentityPoint()}
}

// Base returns group's base point a.k.a. canonical generator.
func (g Group) Base() internal.Element {
	return &Element{*edwards25519.NewGeneratorPoint()}
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (g Group) HashToScalar(input, dst []byte) internal.Scalar {
	return &Scalar{*HashToEdwards25519Field(input, dst)}
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the group.
func (g Group) HashToGroup(input, dst []byte) internal.Element {
	return &Element{*HashToEdwards25519(input, dst)}
}

// EncodeToGroup allows arbitrary input to be mapped non-uniformly to points in the Group.
func (g Group) EncodeToGroup(input, dst []byte) internal.Element {
	return &Element{*EncodeToEdwards25519(input, dst)}
}

// Ciphersuite returns the hash-to-curve ciphersuite identifier.
func (g Group) Ciphersuite() string {
	return H2C
}

// ScalarLength returns the byte size of an encoded element.
func (g Group) ScalarLength() uint {
	return canonicalEncodingLength
}

// ElementLength returns the byte size of an encoded element.
func (g Group) ElementLength() uint {
	return canonicalEncodingLength
}
