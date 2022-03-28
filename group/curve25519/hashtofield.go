// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package curve25519

import (
	"crypto"
	"math/big"

	"filippo.io/edwards25519/field"

	"github.com/bytemare/crypto/group/hash2curve"
)

const (
	elementLength = 32

	// p25519 is the prime 2^255 - 19 for the field.
	p25519 = "57896044618658097711785492504343953926634992332820282019728792003956564819949"

	// p252 represents curve25519's subgroup (prime) order
	// = 2^252 + 27742317777372353535851937790883648493
	// p252 = "7237005577332262213973186563042994240857116359379907606001950938285454250989".
)

var prime, _ = new(big.Int).SetString(p25519, 10) // order, _ = new(big.Int).SetString(p252, 10).

// HashToField25519XMD hashes the input and dst to the field and returns a uniformly distributed byte array, that can
// be used as a scalar.
func HashToField25519XMD(id crypto.Hash, input, dst []byte, length int) []byte {
	l := 48
	expLength := 1 * 1 * l // 1 element * ext * security length
	uniform := hash2curve.ExpandXMD(id, input, dst, expLength)

	return reduce(uniform, length)
}

func hashToField25519XMD(id crypto.Hash, input, dst []byte, count int) (u [2]*field.Element) {
	l := 48
	expLength := count * 1 * l // 1 element * ext * security length
	uniform := hash2curve.ExpandXMD(id, input, dst, expLength)

	for i := 0; i < count; i++ {
		offset := i * l
		u[i] = element(reduce(uniform[offset:offset+l], elementLength))
	}

	return u
}

func reduce(input []byte, length int) []byte {
	/*
		Interpret the input as an integer of the field, and reduce it modulo the prime.
	*/
	i := new(big.Int).SetBytes(input)
	i.Mod(i, prime)

	// If necessary, build a buffer of right size so it gets correctly interpreted.
	b := i.Bytes()
	if l := length - len(b); l > 0 {
		buf := make([]byte, l, length)
		buf = append(buf, b...)
		b = buf
	}

	return reverse(b)
}

func element(input []byte) *field.Element {
	e, err := new(field.Element).SetBytes(input)
	if err != nil {
		panic(err)
	}

	return e
}

func reverse(b []byte) []byte {
	l := len(b) - 1
	for i := 0; i < len(b)/2; i++ {
		b[i], b[l-i] = b[l-i], b[i]
	}

	return b
}
