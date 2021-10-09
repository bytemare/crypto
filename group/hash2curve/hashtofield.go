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

const (
	p25519 = "57896044618658097711785492504343953926634992332820282019728792003956564819949" // 2^255 - 19
	p252   = "7237005577332262213973186563042994240857116359379907606001950938285454250989"  // 2^252 + 27742317777372353535851937790883648493
)

var (
	prime, _    = new(big.Int).SetString(p25519, 10)
	subPrime, _ = new(big.Int).SetString(p252, 10)
)

// HashToField25519XMD hashes the input and dst to the field and returns a uniformly distributed byte array, that can
// be used as a scalar.
func HashToField25519XMD(id crypto.Hash, input, dst []byte, length int) []byte {
	l := 48
	expLength := 1 * 1 * l // 1 element * ext * security length
	uniform := ExpandXMD(id, input, dst, expLength)

	return reduce(uniform, length)
}

// doubleHashToField25519XMD hashes the input and dst to the field and returns two field elements destined to be mapped to
// points on the destination curve.
func doubleHashToField25519XMD(id crypto.Hash, input, dst []byte, length int) (u, v *field.Element) {
	l := 48
	expLength := 2 * 1 * l // 2 elements * ext * security length
	uniform := ExpandXMD(id, input, dst, expLength)
	u = element(reduce(uniform[:l], length))
	v = element(reduce(uniform[l:2*l], length))

	return
}

func reduce(input []byte, length int) []byte {
	/*
		Interpret the input as an integer of the field, and reduce it modulo the prime.
	*/
	i := new(big.Int).SetBytes(input)
	i.Mod(i, subPrime)

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
