// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var (
	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

type field struct {
	prime       *big.Int
	pMinus1div2 *big.Int // used in isSquare
	pMinus2     *big.Int // used for field big.Int inversion
	exp         *big.Int
}

func newField(prime *big.Int) *field {
	// pMinus1div2 is used to determine whether a big Int is a quadratic square.
	pMinus1div2 := big.NewInt(1)
	pMinus1div2.Sub(prime, pMinus1div2)
	pMinus1div2.Rsh(pMinus1div2, 1)

	// pMinus2 is used for modular inversion.
	pMinus2 := big.NewInt(2)
	pMinus2.Sub(prime, pMinus2)

	// precompute e = (p + 1) / 4
	exp := big.NewInt(1)
	exp.Add(prime, exp)
	exp.Rsh(exp, 2)

	return &field{
		prime:       prime,
		pMinus1div2: pMinus1div2,
		pMinus2:     pMinus2,
		exp:         exp,
	}
}

// one sets res to the one big.Int of the finite field.
func (f field) one(res *big.Int) *big.Int {
	return res.Set(one)
}

// random sets res to a random field big.Int.
func (f field) random(res *big.Int) *big.Int {
	tmp, err := rand.Int(rand.Reader, f.prime)
	if err != nil {
		// We can as well not panic and try again in a loop
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	res.Set(tmp)

	return res
}

// order returns the size of the field.
func (f field) order() *big.Int {
	return f.prime
}

// bitLen of prime order.
func (f field) bitLen() int {
	return f.prime.BitLen()
}

// areEqual returns whether both elements are equal.
func (f field) areEqual(f1, f2 *big.Int) bool {
	return f.isZero(f.sub(&big.Int{}, f1, f2))
}

// isZero returns whether the big.Int is equivalent to zero.
func (f field) isZero(e *big.Int) bool {
	return e.Sign() == 0
}

// isSquare returns whether the big.Int is a quadratic square.
func (f field) isSquare(e *big.Int) bool {
	return f.areEqual(f.exponent(&big.Int{}, e, f.pMinus1div2), f.one(&big.Int{}))
}

func (f field) isEqual(f2 *field) bool {
	return f.prime.Cmp(f2.prime) == 0
}

func (f field) mod(x *big.Int) *big.Int {
	return x.Mod(x, f.prime)
}

func (f field) neg(res, x *big.Int) *big.Int {
	return f.mod(res.Neg(x))
}

func (f field) add(res, x, y *big.Int) {
	f.mod(res.Add(x, y))
}

func (f field) sub(res, x, y *big.Int) *big.Int {
	return f.mod(res.Sub(x, y))
}

func (f field) mul(res, x, y *big.Int) {
	f.mod(res.Mul(x, y))
}

func (f field) square(res, x *big.Int) {
	f.mod(res.Mul(x, x))
}

func (f field) inv(res, x *big.Int) {
	f.exponent(res, x, f.pMinus2)
}

// Returns x^n.
func (f field) exponent(res, x, n *big.Int) *big.Int {
	return res.Exp(x, n, f.prime)
}

func (f field) cmov(res, x, y *big.Int, b bool) {
	if b {
		res.Set(y)
	} else {
		res.Set(x)
	}
}

func (f field) sgn0(x *big.Int) int {
	return int(x.Bit(0))
}

func (f field) sqrt3mod4(res, e *big.Int) *big.Int {
	return f.exponent(res, e, f.exp)
}

func (f field) sqrt(res, e *big.Int) *big.Int {
	return f.sqrt3mod4(res, e)
}
