// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package curve448 allows simple and abstracted operations in the Curve448 group.
package curve448

import "github.com/bytemare/crypto/internal"

const (
	// H2CCurve448 represents the hash-to-curve string identifier for Secp256k1.
	H2CCurve448 = "curve448_XOF:SHAKE256_ELL2_RO_"

	// E2CCurve448 represents the encode-to-curve string identifier for Secp256k1.
	E2CCurve448 = "curve448_XOF:SHAKE256_ELL2_NU_"
)

type Group struct{}

func New() internal.Group {
	return Group{}
}

// NewScalar returns a new scalar set to 0.
func (g Group) NewScalar() internal.Scalar {
	return newScalar()
}

// NewElement returns the identity element (point at infinity).
func (g Group) NewElement() internal.Element {
	return newElement()
}

// Base returns the group's base point a.k.a. canonical generator.
func (g Group) Base() internal.Element {
	return newElement().Base()
}

// HashToScalar returns a safe mapping of the arbitrary input to a Scalar.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToScalar(input, dst []byte) internal.Scalar {
	return hashToScalar(input, dst)
}

// HashToGroup returns a safe mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) HashToGroup(input, dst []byte) internal.Element {
	return hashToCurve(input, dst)
}

// EncodeToGroup returns a non-uniform mapping of the arbitrary input to an Element in the Group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func (g Group) EncodeToGroup(input, dst []byte) internal.Element {
	return encodeToCurve(input, dst)
}

// Ciphersuite returns the hash-to-curve ciphersuite identifier.
func (g Group) Ciphersuite() string {
	return H2CCurve448
}

// ScalarLength returns the byte size of an encoded scalar.
func (g Group) ScalarLength() int {
	return scalarLength
}

// ElementLength returns the byte size of an encoded element.
func (g Group) ElementLength() int {
	return elementLength
}

// Order returns the order of the canonical group of scalars.
func (g Group) Order() string {
	return groupOrder
}
