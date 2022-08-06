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
	"crypto"
	"math/big"
	"sync"

	"filippo.io/nistec"
	"github.com/bytemare/hash2curve"

	"github.com/bytemare/crypto/internal"
)

const (
	// H2CP256 represents the hash-to-curve string identifier for P256.
	H2CP256 = "P256_XMD:SHA-256_SSWU_RO_"

	// E2CP256 represents the encode-to-curve string identifier for P256.
	E2CP256 = "P256_XMD:SHA-256_SSWU_NU_"

	// H2CP384 represents the hash-to-curve string identifier for P384.
	H2CP384 = "P384_XMD:SHA-384_SSWU_RO_"

	// E2CP384 represents the encode-to-curve string identifier for P384.
	E2CP384 = "P384_XMD:SHA-384_SSWU_NU_"

	// H2CP521 represents the hash-to-curve string identifier for P521.
	H2CP521 = "P521_XMD:SHA-512_SSWU_RO_"

	// E2CP521 represents the encode-to-curve string identifier for P521.
	E2CP521 = "P521_XMD:SHA-512_SSWU_NU_"
)

func P256() internal.Group {
	initOnceP256.Do(initP256)
	return &p256
}

func P384() internal.Group {
	initOnceP384.Do(initP384)
	return &p384
}

func P521() internal.Group {
	initOnceP521.Do(initP521)
	return &p521
}

// Group represents the prime-order group over the P256 curve.
// It exposes a prime-order group API with hash-to-curve operations.
type Group[Point nistECPoint[Point]] struct {
	h2c         string
	curve       curve[Point]
	scalarField field
}

// NewScalar returns a new, empty, scalar.
func (g Group[P]) NewScalar() internal.Scalar {
	return newScalar(&g.scalarField)
}

// NewElement returns the identity point (point at infinity).
func (g Group[P]) NewElement() internal.Element {
	return &Element[P]{
		p:   g.curve.NewPoint(),
		new: g.curve.NewPoint,
	}
}

// Base returns the group's base point a.k.a. canonical generator.
func (g Group[P]) Base() internal.Element {
	b := g.curve.NewPoint()
	b.SetGenerator()

	return g.newPoint(b)
}

func (g Group[P]) newPoint(p P) *Element[P] {
	return &Element[P]{
		p:   p,
		new: g.curve.NewPoint,
	}
}

// HashToScalar allows arbitrary input to be safely mapped to the field.
func (g Group[P]) HashToScalar(input, dst []byte) internal.Scalar {
	s := hash2curve.HashToFieldXMD(g.curve.hash, input, dst, 1, 1, g.curve.secLength, g.scalarField.prime)[0]

	// If necessary, build a buffer of right size, so it gets correctly interpreted.
	b := s.Bytes()

	length := int(g.ScalarLength())
	if l := length - len(b); l > 0 {
		buf := make([]byte, l, length)
		buf = append(buf, b...)
		b = buf
	}

	return &Scalar{
		s:     new(big.Int).SetBytes(b),
		field: g.curve.field,
	}
}

// HashToGroup allows arbitrary input to be safely mapped to the curve of the group.
func (g Group[P]) HashToGroup(input, dst []byte) internal.Element {
	return g.newPoint(g.curve.hashXMD(input, dst))
}

// EncodeToGroup allows arbitrary input to be mapped non-uniformly to points in the Group.
func (g Group[P]) EncodeToGroup(input, dst []byte) internal.Element {
	return g.newPoint(g.curve.encodeXMD(input, dst))
}

// Ciphersuite returns the hash-to-curve ciphersuite identifier.
func (g Group[P]) Ciphersuite() string {
	return g.h2c
}

// ScalarLength returns the byte size of an encoded element.
func (g Group[P]) ScalarLength() uint {
	byteLen := (g.scalarField.BitLen() + 7) / 8
	return uint(byteLen)
}

// ElementLength returns the byte size of an encoded element.
func (g Group[P]) ElementLength() uint {
	byteLen := (g.curve.field.BitLen() + 7) / 8
	return uint(1 + byteLen)
}

var (
	initOnceP256 sync.Once
	initOnceP384 sync.Once
	initOnceP521 sync.Once

	p256 Group[*nistec.P256Point]
	p384 Group[*nistec.P384Point]
	p521 Group[*nistec.P521Point]
)

func initP256() {
	primeP256, _ := new(big.Int).SetString("115792089210356248762697446949407573530"+
		"086143415290314195533631308867097853951", 10)
	p256.h2c = H2CP256
	p256.curve.setCurveParams(
		primeP256,
		"0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
		nistec.NewP256Point,
	)
	p256.curve.setMapping(crypto.SHA256, "-10", 48)
	p256.setScalarField("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
}

func initP384() {
	primeP384, _ := new(big.Int).SetString("3940200619639447921227904010014361380507973927046544666794"+
		"8293404245721771496870329047266088258938001861606973112319", 10)
	p384.h2c = H2CP384
	p384.curve.setCurveParams(
		primeP384,
		"0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
		nistec.NewP384Point,
	)
	p384.curve.setMapping(crypto.SHA384, "-12", 72)
	p384.setScalarField(
		"0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
	)
}

func initP521() {
	primeP521, _ := new(big.Int).SetString("6864797660130609714981900799081393217269435300143305"+
		"4093944634591855431833976560521225596406614545549772"+
		"96311391480858037121987999716643812574028291115057151", 10)
	p521.h2c = H2CP521
	p521.curve.setCurveParams(
		primeP521,
		"0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef10"+
			"9e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
		nistec.NewP521Point,
	)
	p521.curve.setMapping(crypto.SHA512, "-4", 98)
	p521.setScalarField(
		"0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
			"a51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
	)
}

func (g *Group[Point]) setScalarField(order string) {
	g.scalarField = *NewField(s2int(order))
}
