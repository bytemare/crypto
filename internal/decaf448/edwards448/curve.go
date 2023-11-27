// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package edwards448

import (
	"fmt"
	"github.com/bytemare/crypto/internal/field"
	"github.com/bytemare/hash"
	"math/big"

	"github.com/bytemare/hash2curve"
)

const (
	// 2^448 - 2^224 - 1
	fieldOrder = "726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439"
	// 2^446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
	groupOrder    = "181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779"
	hashing       = hash.SHAKE256
	secLength     = 84
	scalarLength  = 56
	elementLength = 57
)

var (
	fp    = field.NewField(setString(fieldOrder, 10))
	fn    = field.NewField(setString(groupOrder, 10))
	h     = big.NewInt(4)
	d     = big.NewInt(-39081)
	mapZ  = new(big.Int).Mod(big.NewInt(-1), fp.Order())
	baseX = setString("0x297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147eaaf3932d94c63d96c170033f4ba0c7f0de840aed939f", 0)
	baseY = setString("0x13", 0)
)

func setString(s string, base int) *big.Int {
	i := new(big.Int)
	if _, ok := i.SetString(s, base); !ok {
		panic(fmt.Sprintf("setting int in base %d failed: %v", base, s))
	}

	return i
}

func hashToScalar(input, dst []byte) *Scalar {
	s := hash2curve.HashToFieldXOF(hashing, input, dst, 1, 1, secLength, fn.Order())[0]

	// If necessary, build a buffer of right size, so it gets correctly interpreted.
	bytes := s.Bytes()

	length := scalarLength
	if l := length - len(bytes); l > 0 {
		buf := make([]byte, l, length)
		buf = append(buf, bytes...)
		bytes = buf
	}

	res := newScalar()
	res.scalar.SetBytes(bytes)

	return res
}

var (
	secp256k13ISOA = setString("0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533", 0)
	secp256k13ISOB = setString("1771", 0)
)

func map2IsoCurve(fe *big.Int) *Element {
	x, y := hash2curve.MapToCurveSSWU(secp256k13ISOA, secp256k13ISOB, mapZ, fe, fp.Order())
	return newElementWithAffine(x, y)
}

func hashToCurve(input, dst []byte) *Element {
	u := hash2curve.HashToFieldXOF(hashing, input, dst, 2, 1, secLength, fp.Order())
	q0 := map2IsoCurve(u[0])
	q1 := map2IsoCurve(u[1])
	q0.affineAdd(q1) // we use a generic affine add here because the others are tailored for a = 0 and b = 7.
	x, y, isIdentity := hash2curve.IsogenySecp256k13iso(&q0.x, &q0.y)

	if isIdentity {
		return newElement()
	}

	// TODO: clear cofactor
	return newElementWithAffine(x, y)
}

func encodeToCurve(input, dst []byte) *Element {
	u := hash2curve.HashToFieldXOF(hashing, input, dst, 1, 1, secLength, fp.Order())
	q0 := map2IsoCurve(u[0])
	x, y, isIdentity := hash2curve.IsogenySecp256k13iso(&q0.x, &q0.y)

	if isIdentity {
		return newElement()
	}

	// TODO: clear cofactor
	return newElementWithAffine(x, y)
}
