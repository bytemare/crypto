// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package nist implements a prime-order group over NIST P-256 with hash-to-curve.
package nist

import (
	"filippo.io/nistec"
	"github.com/bytemare/crypto/group/internal"
	nist "github.com/bytemare/crypto/group/nist/internal"
)

const (
	// H2CP256 represents the hash-to-curve string identifier for P256.
	H2CP256 = "P256_XMD:SHA-256_SSWU_RO_"

	// H2CP256NU represents the encode-to-curve string identifier for P256.
	H2CP256NU = "P256_XMD:SHA-256_SSWU_NU_"

	// H2CP384 represents the hash-to-curve string identifier for P384.
	H2CP384 = "P384_XMD:SHA-384_SSWU_RO_"

	// H2CP384NU represents the encode-to-curve string identifier for P384.
	H2CP384NU = "P384_XMD:SHA-384_SSWU_NU_"

	// H2CP521 represents the hash-to-curve string identifier for P521.
	H2CP521 = "P521_XMD:SHA-512_SSWU_RO_"

	// H2CP521NU represents the encode-to-curve string identifier for P521.
	H2CP521NU = "P521_XMD:SHA-512_SSWU_NU_"
)

// Group represents the prime-order group over the P256 curve.
// It exposes a prime-order group API with hash-to-curve operations.
type Group[Point nist.NistECPoint[Point]] struct {
	h2c   string
	group *nist.Group[Point]
}

func P256() internal.Group {
	return &Group[*nistec.P256Point]{H2CP256, nist.P256()}
}

func P384() internal.Group {
	return &Group[*nistec.P384Point]{H2CP384, nist.P384()}
}

func P521() internal.Group {
	return &Group[*nistec.P521Point]{H2CP521, nist.P521()}
}

// NewScalar returns a new, empty, scalar.
func (g Group[any]) NewScalar() internal.Scalar {
	return &Scalar[any]{
		group:  g.group,
		scalar: g.group.NewScalar(),
	}
}

// ElementLength returns the byte size of an encoded element.
func (g Group[any]) ElementLength() uint {
	return g.group.PointLength()
}

func (g Group[any]) newPoint(p *nist.Element[any]) *Point[any] {
	return &Point[any]{
		group: g.group,
		point: p,
	}
}

// NewElement returns the identity point (point at infinity).
func (g Group[any]) NewElement() internal.Element {
	return g.newPoint(g.group.NewPoint())
}

// Identity returns the group's identity element.
func (g Group[any]) Identity() internal.Element {
	return g.NewElement()
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the group.
func (g Group[any]) HashToGroup(input, dst []byte) internal.Element {
	return g.newPoint(g.group.HashToGroup(input, dst))
}

// EncodeToGroup allows arbitrary input to be mapped non-uniformly to points in the Group.
func (g Group[any]) EncodeToGroup(input, dst []byte) internal.Element {
	return g.newPoint(g.group.EncodeToGroup(input, dst))
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (g Group[any]) HashToScalar(input, dst []byte) internal.Scalar {
	return &Scalar[any]{
		group:  g.group,
		scalar: g.group.HashToScalar(input, dst),
	}
}

// Base returns group's base point a.k.a. canonical generator.
func (g Group[any]) Base() internal.Element {
	return g.newPoint(g.group.Base())
}

// MultBytes allows []byte encodings of a scalar and an element of the group to be multiplied.
func (g Group[any]) MultBytes(s, e []byte) (internal.Element, error) {
	p, err := g.group.MultBytes(s, e)
	if err != nil {
		return nil, err
	}

	return g.newPoint(p), nil
}

// Ciphersuite returns the hash-to-curve ciphersuite identifier.
func (g Group[any]) Ciphersuite() string {
	return g.h2c
}
