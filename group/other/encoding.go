// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package other wraps a hash-to-curve implementation and exposes functions for operations on points and scalars.
package other

import (
	"math/big"

	"github.com/bytemare/crypto/group/internal"
)

func pointLen(bitLen int) int {
	byteLen := (bitLen + 7) / 8
	return 1 + byteLen
}

func encodeSignPrefix(x, y *big.Int, pointLen int) []byte {
	compressed := make([]byte, pointLen)
	compressed[0] = byte(y.Bit(0)) | 2
	x.FillBytes(compressed[1:])

	return compressed
}

// y^2 = x^3 + b.
func solveKoblitz(x *big.Int) *big.Int {
	var a int64 = 7

	y := new(big.Int).Mul(x, x)

	y.Mul(y, x)
	y.Add(y, big.NewInt(a))

	return y.Mod(y, secp256k1order)
}

// y^2 = ( x^3 + A * x^2 + x ) / B, with B = 1.
func solveCurve448(x *big.Int) *big.Int {
	x2 := new(big.Int).Mul(x, x)
	x3 := new(big.Int).Mul(x2, x)
	ax2 := new(big.Int).Mul(x2, curve448a)
	y2 := new(big.Int).Add(x3, ax2)
	y2.Add(y2, x)

	return y2.Mod(y2, curve448order)
}

// y^2 = ( 1 - x^2 ) / ( 1 − d * x^2 ).
func solveEd448(x *big.Int) *big.Int {
	x2 := new(big.Int).Mul(x, x)
	dx2 := new(big.Int).Mul(ed448d, x2)
	x2.Sub(big.NewInt(1), x2)
	dx2.Sub(big.NewInt(1), dx2)
	dx2.ModInverse(dx2, ed448order)
	y2 := new(big.Int).Mul(x2, dx2)

	return y2.Mod(y2, ed448order)
}

func (p *Point) recoverPoint(input []byte) (*Point, error) {
	// Extract x
	x, err := getX(p.Field(), input)
	if err != nil {
		return nil, err
	}

	// Compute y^2
	y := p.solver(x)
	y.ModSqrt(y, p.Field().Order())

	if y == nil {
		return nil, errParamYNotSquare
	}

	// Set the sign
	if byte(y.Bit(0)) != input[0]&1 {
		y.Neg(y).Mod(y, p.Field().Order())
	}

	// Verify the point is on curve
	if err := isOnCurve(x, y, p.Field().Order(), p.solver); err != nil {
		return nil, err
	}

	if err := p.set(x, y); err != nil {
		return nil, err
	}

	if p.point.IsIdentity() {
		return nil, internal.ErrIdentity
	}

	return p, nil
}

type solver func(x *big.Int) *big.Int

func isOnCurve(x, y, order *big.Int, solve solver) error {
	// Reject integers below 0 or higher than the field order.
	if x.Sign() < 0 || x.Cmp(order) >= 0 ||
		y.Sign() < 0 || y.Cmp(order) >= 0 {
		return errParamNotOnCurve
	}

	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, order)

	if solve(x).Cmp(y2) != 0 {
		return errParamNotOnCurve
	}

	return nil
}
