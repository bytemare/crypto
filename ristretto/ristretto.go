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

	"github.com/gtank/ristretto255"

	"github.com/bytemare/crypto/hash2curve"
	"github.com/bytemare/crypto/internal"
)

const (
	ristrettoInputLength = 64

	// H2C represents the hash-to-curve string identifier.
	H2C = "ristretto255_XMD:SHA-512_R255MAP_RO_"
)

// Group represents the Ristretto255 group. It exposes a prime-order group API with hash-to-curve operations.
type Group struct{}

func New() internal.Group {
	return Group{}
}

// NewScalar returns a new, empty, scalar.
func (r Group) NewScalar() internal.Scalar {
	return &Scalar{ristretto255.NewScalar()}
}

// ElementLength returns the byte size of an encoded element.
func (r Group) ElementLength() uint {
	return canonicalEncodingLength
}

// NewElement returns the identity element (point at infinity).
func (r Group) NewElement() internal.Element {
	return &Point{ristretto255.NewElement()}
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the group.
func (r Group) HashToGroup(input, dst []byte) internal.Element {
	uniform := hash2curve.ExpandXMD(crypto.SHA512, input, dst, ristrettoInputLength)

	return &Point{ristretto255.NewElement().FromUniformBytes(uniform)}
}

// EncodeToGroup allows arbitrary input to be mapped non-uniformly to points in the Group.
func (r Group) EncodeToGroup(input, dst []byte) internal.Element {
	return r.HashToGroup(input, dst)
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (r Group) HashToScalar(input, dst []byte) internal.Scalar {
	uniform := hash2curve.ExpandXMD(crypto.SHA512, input, dst, ristrettoInputLength)

	return &Scalar{ristretto255.NewScalar().FromUniformBytes(uniform)}
}

// Base returns group's base point a.k.a. canonical generator.
func (r Group) Base() internal.Element {
	return &Point{ristretto255.NewElement().Base()}
}

// MultBytes allows []byte encodings of a scalar and an element of the group to be multiplied.
func (r Group) MultBytes(s, e []byte) (internal.Element, error) {
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

// Ciphersuite returns the hash-to-curve ciphersuite identifier.
func (r Group) Ciphersuite() string {
	return H2C
}
