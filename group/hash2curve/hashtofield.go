// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package hash2curve

import (
	"crypto"
	"math/big"

	"filippo.io/edwards25519/field"
)

const p25519 = "57896044618658097711785492504343953926634992332820282019728792003956564819949"

var prime, _ = new(big.Int).SetString(p25519, 10)

// HashToScalarXMD hashes the input and dst to the field and returns a uniformly distributed byte array, that can
// be used as a scalar.
func HashToScalarXMD(id crypto.Hash, input, dst []byte, length int) []byte {
	l := 48
	expLength := 1 * 1 * l // 1 element * ext * security length
	uniform := ExpandXMD(id, input, dst, expLength)

	return innerh2f(uniform, length)
}

// HashToFieldXMD hashes the input and dst to the field and returns two field elements destined to be mapped to
// points on the destination curve.
func HashToFieldXMD(id crypto.Hash, input, dst []byte, length int) (u, v *field.Element) {
	l := 48
	expLength := 2 * 1 * l // 2 elements * ext * security length
	uniform := ExpandXMD(id, input, dst, expLength)
	u = innerh2fe(uniform[:l], length)
	v = innerh2fe(uniform[l:2*l], length)

	return
}

func innerh2f(input []byte, length int) []byte {
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

func innerh2fe(input []byte, length int) *field.Element {
	b := innerh2f(input, length)

	e, err := new(field.Element).SetBytes(b)
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
