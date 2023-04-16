// SPDX-License-Identifier: MIT
//
// Copyright (C)2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package group_test

import (
	"testing"

	"github.com/bytemare/crypto"
)

func testAll(t *testing.T, f func(*testing.T, *testGroup)) {
	for _, test := range testTable {
		t.Run(test.name, func(t *testing.T) {
			f(t, test)
		})
	}
}

// a testGroup references some parameters of a Group.
type testGroup struct {
	name          string
	h2c           string
	e2c           string
	basePoint     string
	identity      string
	elementLength int
	scalarLength  int
	group         crypto.Group
}

var testTable = []*testGroup{
	{
		"Ristretto255",
		"ristretto255_XMD:SHA-512_R255MAP_RO_",
		"ristretto255_XMD:SHA-512_R255MAP_RO_",
		ristrettoBasePoint,
		"0000000000000000000000000000000000000000000000000000000000000000",
		32,
		32,
		1,
	},
	{
		"P256",
		"P256_XMD:SHA-256_SSWU_RO_",
		"P256_XMD:SHA-256_SSWU_NU_",
		"036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
		"000000000000000000000000000000000000000000000000000000000000000000",
		33,
		32,
		3,
	},
	{
		"P384",
		"P384_XMD:SHA-384_SSWU_RO_",
		"P384_XMD:SHA-384_SSWU_NU_",
		"03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		49,
		48,
		4,
	},
	{
		"P521",
		"P521_XMD:SHA-512_SSWU_RO_",
		"P521_XMD:SHA-512_SSWU_NU_",
		"0200c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
		67,
		66,
		5,
	},
	{
		"Edwards25519",
		"edwards25519_XMD:SHA-512_ELL2_RO_",
		"edwards25519_XMD:SHA-512_ELL2_NU_",
		"5866666666666666666666666666666666666666666666666666666666666666",
		"0100000000000000000000000000000000000000000000000000000000000000",
		32,
		32,
		6,
	},
	{
		"Secp256k1",
		"secp256k1_XMD:SHA-256_SSWU_RO_",
		"secp256k1_XMD:SHA-256_SSWU_NU_",
		"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"000000000000000000000000000000000000000000000000000000000000000000",
		33,
		32,
		7,
	},
}
