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
	"errors"
	"log"
	"math/big"

	"github.com/bytemare/crypto/group/internal"
)

func pointLen(bitLen int) uint {
	byteLen := (bitLen + 7) / 8
	return uint(1 + byteLen)
}

func encodeSignPrefix(x, y *big.Int, pointLen uint) []byte {
	compressed := make([]byte, pointLen)
	compressed[0] = byte(y.Bit(0)) | 2
	x.FillBytes(compressed[1:])

	return compressed
}

func reverse(b []byte) []byte {
	length := cap(b)
	for i := 0; i < length/2; i++ {
		b[i], b[length-i-1] = b[length-i-1], b[i]
	}

	return b
}

func encodeSignPrefix448(x, y *big.Int, pointLen uint) []byte {
	compressed := make([]byte, pointLen)
	xb := make([]byte, pointLen-1)
	xb = reverse(x.FillBytes(xb))
	log.Printf("xb: %v", xb)
	sign := (xb[0] & 1) << 7
	compressed[pointLen-1] = sign
	log.Println(compressed)
	//y.FillBytes(compressed[:pointLen-1])
	copy(compressed[:pointLen-1], reverse(y.Bytes()))

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
func solveCurve448y(x *big.Int) *big.Int {
	x2 := new(big.Int).Mul(x, x)
	x3 := new(big.Int).Mul(x2, x)
	ax2 := new(big.Int).Mul(x2, curve448a)
	y2 := new(big.Int).Add(x3, ax2)
	y2.Add(y2, x)

	return y2.Mod(y2, curve448order)
}

func solveCurve448x(y *big.Int) *big.Int {
	y2 := new(big.Int).Mul(y, y) // y^2
	dy2 := new(big.Int).Mul(y2, curve448a)
	y2min1 := new(big.Int).Sub(y2, big.NewInt(1))
	dy2min1 := new(big.Int).Sub(dy2, big.NewInt(1))

	return new(big.Int).Div(y2min1, dy2min1)
}

func solveEdwards448x(y *big.Int) *big.Int {
	y2 := new(big.Int).Mul(y, y) // y^2
	dy2 := new(big.Int).Mul(y2, curve448a)
	y2min1 := new(big.Int).Sub(y2, big.NewInt(1))
	dy2min1 := new(big.Int).Sub(dy2, big.NewInt(1))

	return new(big.Int).Div(y2min1, dy2min1)
}

// y^2 = ( 1 - x^2 ) / ( 1 − d * x^2 ).
func solveEd448y(x *big.Int) *big.Int {
	x2 := new(big.Int).Mul(x, x)        // x^2
	dx2 := new(big.Int).Mul(ed448d, x2) //
	x2.Sub(big.NewInt(1), x2)
	dx2.Sub(big.NewInt(1), dx2)
	dx2.ModInverse(dx2, ed448order)
	y2 := new(big.Int).Mul(x2, dx2)

	return y2.Mod(y2, ed448order)
}

func (p *Point) recover448(input []byte) (*Point, error) {
	// Extract y
	y, err := getY(p.Field(), input)
	if err != nil {
		return nil, err
	}

	byteLen := (p.Field().BitLen() + 7) / 8
	signX := uint(input[byteLen] >> 7)

	// Compute y^2
	x := p.solver(y)

	x.ModSqrt(x, p.Field().Order())
	if x == nil {
		return nil, errParamYNotSquare
	}

	if x.Cmp(big.NewInt(0)) == 0 && signX == 1 {
		return nil, errors.New("invalid decoding")
	}

	if signX != (x.Bit(0) & 1) {
		x.Neg(x)
		x.Mod(x, p.Field().Order())
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
