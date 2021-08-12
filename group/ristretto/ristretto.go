// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ristretto wraps "github.com/gtank/ristretto255" and exposes a simple prime-order group API with hash-to-curve.
package ristretto

import (
	"crypto"

	"github.com/gtank/ristretto255"

	"github.com/bytemare/cryptotools/group/hash2curve"
	"github.com/bytemare/cryptotools/group/internal"
)

const (
	ristrettoInputLength = 64

	// H2C represents the hash-to-curve string identifier.
	H2C = "ristretto255_XMD:SHA-512_R255MAP_RO_"
)

// Ristretto255Sha512 represents the Ristretto255 group. It exposes a prime-order group API with hash-to-curve operations.
type Ristretto255Sha512 struct{}

// NewScalar returns a new, empty, scalar.
func (r Ristretto255Sha512) NewScalar() internal.Scalar {
	return &Scalar{ristretto255.NewScalar()}
}

// ElementLength returns the byte size of an encoded element.
func (r Ristretto255Sha512) ElementLength() int {
	return canonicalEncodingLength
}

// NewElement returns a new, empty, element.
func (r Ristretto255Sha512) NewElement() internal.Point {
	return &Point{ristretto255.NewElement()}
}

// Identity returns the group's identity element.
func (r Ristretto255Sha512) Identity() internal.Point {
	return &Point{ristretto255.NewElement().Zero()}
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the group.
func (r Ristretto255Sha512) HashToGroup(input, dst []byte) internal.Point {
	uniform := hash2curve.ExpandXMD(crypto.SHA512, input, dst, ristrettoInputLength)

	return &Point{ristretto255.NewElement().FromUniformBytes(uniform)}
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (r Ristretto255Sha512) HashToScalar(input, dst []byte) internal.Scalar {
	uniform := hash2curve.ExpandXMD(crypto.SHA512, input, dst, ristrettoInputLength)

	return &Scalar{ristretto255.NewScalar().FromUniformBytes(uniform)}
}

// Base returns group's base point a.k.a. canonical generator.
func (r Ristretto255Sha512) Base() internal.Point {
	return &Point{ristretto255.NewElement().Base()}
}

// MultBytes allows []byte encodings of a scalar and an element of the group to be multiplied.
func (r Ristretto255Sha512) MultBytes(s, e []byte) (internal.Point, error) {
	sc, err := r.NewScalar().Decode(s)
	if err != nil {
		return nil, err
	}

	el, err := r.NewElement().Decode(e)
	if err != nil {
		return nil, err
	}

	return el.Mult(sc), nil
}
