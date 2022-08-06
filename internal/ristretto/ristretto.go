// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ristretto wraps github.com/gtank/ristretto255 and exposes a simple prime-order group API with hash-to-curve.
package ristretto

import (
	"crypto"

	"github.com/bytemare/hash2curve"
	"github.com/gtank/ristretto255"

	"github.com/bytemare/crypto/internal"
)

const (
	inputLength = 64

	// H2C represents the hash-to-curve string identifier.
	H2C = "ristretto255_XMD:SHA-512_R255MAP_RO_"
)

// Group represents the Ristretto255 group. It exposes a prime-order group API with hash-to-curve operations.
type Group struct{}

func New() internal.Group {
	return Group{}
}

// NewScalar returns a new, empty, scalar.
func (g Group) NewScalar() internal.Scalar {
	return &Scalar{*ristretto255.NewScalar()}
}

// NewElement returns the identity element (point at infinity).
func (g Group) NewElement() internal.Element {
	return &Element{*ristretto255.NewElement()}
}

// Base returns group's base point a.k.a. canonical generator.
func (g Group) Base() internal.Element {
	return &Element{*ristretto255.NewElement().Base()}
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (g Group) HashToScalar(input, dst []byte) internal.Scalar {
	uniform := hash2curve.ExpandXMD(crypto.SHA512, input, dst, inputLength)
	return &Scalar{*ristretto255.NewScalar().FromUniformBytes(uniform)}
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the group.
func (g Group) HashToGroup(input, dst []byte) internal.Element {
	uniform := hash2curve.ExpandXMD(crypto.SHA512, input, dst, inputLength)

	return &Element{*ristretto255.NewElement().FromUniformBytes(uniform)}
}

// EncodeToGroup allows arbitrary input to be mapped non-uniformly to points in the Group.
func (g Group) EncodeToGroup(input, dst []byte) internal.Element {
	return g.HashToGroup(input, dst)
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
