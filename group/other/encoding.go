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
	"math/big"
)

// const ed25519PointSize = 32

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

// func encodeEd25519(x, y *big.Int) []byte {
//	out := make([]byte, ed25519PointSize)
//	y.FillBytes(out)
//	out[0] |= byte(x.Bit(0) << 7)
//
//	return out
// }

// func decodeEd25519(in []byte) (x, y *big.Int, err error) {
//	if len(in) != ed25519PointSize {
//		return nil, nil, errParamInvalidEd25519Enc
//	}
//
//	xsign := in[0] >> 7
//	mask := ^(1 << 7)
//	in[0] &= byte(mask)
//
//	// Get y
//	y = new(big.Int).SetBytes(in)
//	if y.Cmp(ed25519order) >= 0 {
//		return nil, nil, errParamDecXExceeds
//	}
//
//	// Compute x
//	x = solveEd25519X(y)
//	x.ModSqrt(x, ed25519order)
//
//	if x == nil {
//		return nil, nil, errParamXNotSquare
//	}
//
//	// Set the sign
//	if x.Bit(0) != uint(xsign) {
//		x.Neg(x).Mod(x, ed25519order)
//	}
//
//	if err := isOnCurve(x, y, ed25519order, solveEd25519Y); err != nil {
//		return nil, nil, err
//	}
//
//	return x, y, nil
//}

type solver func(x *big.Int) *big.Int

func isOnCurve(x, y, order *big.Int, solve solver) error {
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, order)

	if solve(x).Cmp(y2) != 0 {
		return errParamNotOnCurve
	}

	return nil
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

// y^2 = ( x^3 + A * x^2 + x ) / B, with B = 1.
// func solveCurve25519(x *big.Int) *big.Int {
//	x2 := new(big.Int).Mul(x, x)
//	x3 := new(big.Int).Mul(x2, x)
//	ax2 := new(big.Int).Mul(x2, curve25519a)
//	y2 := new(big.Int).Add(x3, ax2)
//	y2.Add(y2, x)
//
//	return y2.Mod(y2, curve25519order)
// }

// y^2 = ( 1 + x^2 ) / ( 1 − d * x^2 ).
// func solveEd25519Y(x *big.Int) *big.Int {
//	x2 := new(big.Int).Mul(x, x)
//	dx2 := new(big.Int).Mul(ed25519d, x2)
//	x2.Add(big.NewInt(1), x2)
//	dx2.Sub(big.NewInt(1), dx2)
//	dx2.ModInverse(dx2, ed25519order)
//	y2 := new(big.Int).Mul(x2, dx2)
//
//	return y2.Mod(y2, ed25519order)
// }

// x^2 = ( y^2 - 1 ) / ( 1 + d * y^2 ).
// func solveEd25519X(y *big.Int) *big.Int {
//	y2 := new(big.Int).Mul(y, y)
//	dy2 := new(big.Int).Mul(ed25519d, y2)
//	dy2.Add(big.NewInt(1), dy2)
//	y2.Sub(y2, big.NewInt(1))
//	dy2.ModInverse(dy2, ed25519order)
//	x2 := new(big.Int).Mul(y2, dy2)
//
//	return x2.Mod(x2, ed25519order)
// }

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

	return p, nil
}
