// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package d448

import (
	"errors"
	"fmt"
	"github.com/bytemare/crypto/internal"
	"github.com/bytemare/crypto/internal/field"
	"github.com/bytemare/hash"
	"log"
	"math/big"

	"github.com/bytemare/hash2curve"
)

const (
	// 2^448 - 2^224 - 1
	fieldOrder = "726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439"
	// 2^446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
	groupOrder    = "181709681073901722637330951972001133588410340171829515070372549795146003961539585716195755291692375963310293709091662304773755859649779"
	hashing       = hash.SHAKE256
	secLength     = 224
	scalarLength  = 56
	elementLength = 56
)

var (
	Fp = field.NewField(setString(fieldOrder, 10))
	fn = field.NewField(setString(groupOrder, 10))
	//d             = big.NewInt(-39081)
	d             = setString("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018326358", 10)
	d4            = big.NewInt(-156324) // d4 = 4 * d
	oneMinusD     = big.NewInt(39082)
	oneMinusTwoD  = big.NewInt(78163)
	sqrtMinusD    = setString("98944233647732219769177004876929019128417576295529901074099889598043702116001257856802131563896515373927712232092845883226922417596214", 10)
	invSqrtMinusD = setString("315019913931389607337177038330951043522456072897266928557328499619017160722351061360252776265186336876723201881398623946864393857820716", 10)
	pMinus3Div4   = setString("181709681073901722637330951972001133588410340171829515070372549795153082041682693171599095924669136482522221115460909340263374504591359", 10)
	mapZ          = new(big.Int).Mod(big.NewInt(-1), Fp.Order())
	baseX         = setString("297ea0ea2692ff1b4faff46098453a6a26adf733245f065c3c59d0709cecfa96147eaaf3932d94c63d96c170033f4ba0c7f0de840aed939f", 16)
	baseY         = setString("13", 16)
)

func SqrtRatioM2(u, v *big.Int) (bool, *big.Int) {
	var t0, t1, r big.Int

	Fp.Mul(&t0, u, v)
	Fp.Square(&t1, v)
	Fp.Mul(&t1, &t0, &t1)
	Fp.Exponent(&r, &t1, pMinus3Div4)
	Fp.Mul(&r, &r, &t0)

	Fp.Square(&t0, &r)
	Fp.Mul(&t0, &t0, v)
	Fp.Sub(&t0, &t0, u)

	return Fp.IsZero(&t0), &r
}

func SqrtRatioM1(u, v *big.Int) (bool, *big.Int) {
	var r, check big.Int

	Fp.Mul(&r, u, v)
	Fp.Exponent(&r, &r, pMinus3Div4) // r = (1/r) mod p
	Fp.Mul(&r, &r, u)

	Fp.Square(&check, &r)
	Fp.Mul(&check, &check, v)
	wasSquare := Fp.AreEqual(&check, u)
	log.Printf("c : %v", check.String())
	log.Printf("u : %v", u.String())
	var ratio big.Int
	Fp.Inv(&ratio, v)
	Fp.Mul(&ratio, &ratio, u)
	log.Printf("Ration: %v", ratio.String())
	log.Printf("Sq: %v", wasSquare)

	return wasSquare, ctAbs(&r)
}

// ctSet sets result to u if cond is true, and to v otherwise. Returns result.
func ctSet(cond bool, result, u, v *big.Int) *big.Int {
	result.Set(ctSelect(cond, u, v))
	return result
}

// ctAbs sets u to its absolute value.
func ctAbs(u *big.Int) *big.Int {
	ctSet(u.Sign() == -1, u, new(big.Int).Neg(u), u)
	return u
}

// ctSelect returns u if cond is true, and v otherwise.
func ctSelect(cond bool, u, v *big.Int) *big.Int {
	if cond {
		return u
	}

	return v
}

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

func hashToDecaf(input, dst []byte) internal.Element {
	expLength := 2 * 1 * secLength
	uniform := hash2curve.ExpandXOF(hashing, input, dst, expLength)
	log.Printf("Decaf uniform expanded length: %d", len(uniform))

	if len(input) != 112 {
		panic(errors.New("invalid input length"))
	}

	p1 := mapToDecaf(uniform[:56])
	p2 := mapToDecaf(uniform[56:])

	return p1.add(p2)
}

func mapToDecaf(data []byte) *Element {
	rbytes := make([]byte, 56)
	copy(rbytes, data)
	rbytes = reverse(rbytes)

	t := new(big.Int).SetBytes(rbytes)
	Fp.Mod(t)

	var r, u0, t1, t2, u1, w0, w1, w2, w3, s, ss, minusOne big.Int
	Fp.Square(&r, t)
	Fp.Neg(&r, &r)
	Fp.Sub(&u1, &r, Fp.One())
	Fp.Mul(&u1, &u1, d)

	Fp.Add(&t1, &u0, Fp.One())
	Fp.Sub(&t2, &u0, &r)
	Fp.Mul(&u1, &t1, &t2)

	Fp.Add(&t1, &r, Fp.One())
	Fp.Mul(&t2, &t1, &u1)
	wasSquare, v := SqrtRatioM1(oneMinusTwoD, &t2)
	Fp.Mul(&t2, t, v)
	vPrime := ctSelect(wasSquare, &t2, v)
	Fp.Sub(&minusOne, Fp.Zero(), Fp.One())
	sgn := ctSelect(wasSquare, &minusOne, Fp.One())
	Fp.Mul(&s, vPrime, &t1)

	w0 = *ctAbs(&s)
	Fp.Add(&w0, &w0, &w0)
	Fp.Square(&ss, &s)
	Fp.Add(&w1, &ss, Fp.One())
	Fp.Sub(&w2, &ss, Fp.One())

	Fp.Mul(&w3, vPrime, &s)
	Fp.Sub(&t1, &r, Fp.One())
	Fp.Mul(&w3, &w3, &t1)
	Fp.Mul(&w3, &w3, oneMinusTwoD)
	Fp.Add(&w3, &w3, sgn)

	e := &Element{
		x: big.Int{},
		y: big.Int{},
		z: big.Int{},
		t: big.Int{},
	}

	Fp.Mul(&e.x, &w0, &w3)
	Fp.Mul(&e.y, &w2, &w1)
	Fp.Mul(&e.z, &w1, &w3)
	Fp.Mul(&e.t, &w0, &w2)

	return e
}
