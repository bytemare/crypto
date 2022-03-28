// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package other wraps an hash-to-curve implementation and exposes functions for operations on points and scalars.
package other

import (
	"crypto/elliptic"
	"math/big"

	H2C "github.com/armfazh/h2c-go-ref"
	C "github.com/armfazh/h2c-go-ref/curve"
	Curve "github.com/armfazh/tozan-ecc/curve"
)

type curve struct {
	id C.ID
	Curve.EllCurve
	solver
	base Curve.Point
}

var (
	curve448a, _   = new(big.Int).SetString("156326", 0)
	curve448order  = C.Curve448.Get().Field().Order()
	ed448d, _      = new(big.Int).SetString("-39081", 0)
	ed448order     = C.Edwards448.Get().Field().Order()
	secp256k1order = C.SECP256K1.Get().Field().Order()
)

func point(curve Curve.EllCurve, x, y string) Curve.Point {
	X := curve.Field().Elt(x)
	Y := curve.Field().Elt(y)

	return curve.NewPoint(X, Y)
}

type params struct {
	id C.ID
	solver
	baseX, baseY string
}

func h2cToNist(id C.ID) elliptic.Curve {
	if id == C.P256 {
		return elliptic.P256()
	}

	if id == C.P384 {
		return elliptic.P384()
	}

	if id == C.P521 {
		return elliptic.P521()
	}

	panic("not a nist curve")
}

func (p *params) New(ec Curve.EllCurve) *curve {
	base := point(ec, p.baseX, p.baseY)

	return &curve{
		id:       p.id,
		EllCurve: p.id.Get(),
		solver:   p.solver,
		base:     base,
	}
}

var curves = map[H2C.SuiteID]*params{
	H2C.P256_XMDSHA256_SSWU_RO_: {
		C.P256,
		nil,
		"0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
		"0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	},
	H2C.P384_XMDSHA384_SSWU_RO_: {
		C.P384,
		nil,
		"0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
		"0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
	},
	H2C.P521_XMDSHA512_SSWU_RO_: {
		C.P521,
		nil,
		"0xc6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d" +
			"3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
		"0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273" +
			"e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
	},
	H2C.Curve448_XMDSHA512_ELL2_RO_: {
		C.Curve448,
		solveCurve448,
		"0x5",
		"0x7D235D1295F5B1F66C98AB6E58326FCECBAE5D34F55545D060F75DC" +
			"28DF3F6EDB8027E2346430D211312C4B150677AF76FD7223D457B5B1A",
	},
	H2C.Edwards448_XMDSHA512_ELL2_RO_: {
		C.Edwards448,
		solveEd448,
		"0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d07" +
			"09cecfa96147eaaf3932d94c63d96c170033f4ba0c7f0de840aed939f",
		"0x13",
	},
	H2C.Secp256k1_XMDSHA256_SSWU_RO_: {
		C.SECP256K1,
		solveKoblitz,
		"0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
	},
}
