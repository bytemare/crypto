// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist

import (
	"crypto"
	"math/big"

	"github.com/bytemare/hash2curve"
)

func s2int(s string) *big.Int {
	if p, _ := new(big.Int).SetString(s, 0); p != nil {
		return p
	}

	panic("invalid string to convert")
}

type mapping struct {
	hash      crypto.Hash
	secLength int
	z         *big.Int
}

type curve[point nistECPoint[point]] struct {
	field    *field
	a, b     *big.Int
	NewPoint func() point
	mapping
}

func (c *curve[point]) setMapping(hash crypto.Hash, z string, secLength int) {
	c.mapping.hash = hash
	c.mapping.secLength = secLength
	c.mapping.z = s2int(z)
}

func (c *curve[point]) setCurveParams(prime *big.Int, b string, newPoint func() point) {
	c.field = newField(prime)
	c.a = s2int("-3")
	c.b = s2int(b)
	c.NewPoint = newPoint
}

func (c *curve[point]) encodeXMD(input, dst []byte) point {
	u := hash2curve.HashToFieldXMD(c.hash, input, dst, 1, 1, c.secLength, c.field.prime)
	q := c.map2curve(u[0])
	// We can save cofactor clearing because it is 1.
	return q
}

func (c *curve[point]) hashXMD(input, dst []byte) point {
	u := hash2curve.HashToFieldXMD(c.hash, input, dst, 2, 1, c.secLength, c.field.prime)
	q0 := c.map2curve(u[0])
	q1 := c.map2curve(u[1])
	// We can save cofactor clearing because it is 1.
	return q0.Add(q0, q1)
}

func (c *curve[point]) sqrtRatio(e, v *big.Int) (bool, *big.Int) {
	var result big.Int
	field := c.field
	field.inv(&result, v)
	field.mul(&result, &result, e)

	if field.isSquare(&result) {
		return true, field.sqrt(&result, &result)
	}

	field.mul(&result, &result, c.z)

	return false, field.sqrt(&result, &result)
}

// map2curve implements the Simplified SWU method.
func (c *curve[point]) map2curve(input *big.Int) point {
	var tv1, tv2, tv3, tv4, tv5, tv6, _px, _py big.Int

	c.field.square(&tv1, input)   //    1.  tv1 = u^2
	c.field.mul(&tv1, c.z, &tv1)  //    2.  tv1 = Z * tv1
	c.field.square(&tv2, &tv1)    //    3.  tv2 = tv1^2
	c.field.add(&tv2, &tv2, &tv1) //    4.  tv2 = tv2 + tv1
	c.field.add(&tv3, &tv2, one)  //    5.  tv3 = tv2 + 1
	c.field.mul(&tv3, c.b, &tv3)  //    6.  tv3 = B * tv3
	c.field.cmov(&tv4, c.z,
		c.field.neg(&big.Int{}, &tv2),
		!c.field.isZero(&tv2)) //    7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	c.field.mul(&tv4, c.a, &tv4)  //    8.  tv4 = A * tv4
	c.field.square(&tv2, &tv3)    //    9.  tv2 = tv3^2
	c.field.square(&tv6, &tv4)    //    10. tv6 = tv4^2
	c.field.mul(&tv5, c.a, &tv6)  //    11. tv5 = A * tv6
	c.field.add(&tv2, &tv2, &tv5) //    12. tv2 = tv2 + tv5
	c.field.mul(&tv2, &tv2, &tv3) //    13. tv2 = tv2 * tv3
	c.field.mul(&tv6, &tv6, &tv4) //    14. tv6 = tv6 * tv4
	c.field.mul(&tv5, c.b, &tv6)  //    15. tv5 = B * tv6
	c.field.add(&tv2, &tv2, &tv5) //    16. tv2 = tv2 + tv5
	c.field.mul(&_px, &tv1, &tv3) //    17.   x = tv1 * tv3

	isGx1Square, y1 := c.sqrtRatio(&tv2, &tv6) //    18. (is_gx1_square, y1) = sqrt_ratio(tv2, tv6)

	c.field.mul(&_py, &tv1, input)                              //    19.   y = tv1 * u
	c.field.mul(&_py, &_py, y1)                                 //    20.   y = y * y1
	c.field.cmov(&_px, &_px, &tv3, isGx1Square)                 //    21.   x = CMOV(x, tv3, is_gx1_square)
	c.field.cmov(&_py, &_py, y1, isGx1Square)                   //    22.   y = CMOV(y, y1, is_gx1_square)
	e1 := c.field.sgn0(input) == c.field.sgn0(&_py)             //    23.  e1 = sgn0(u) == sgn0(y)
	c.field.cmov(&_py, c.field.neg(&big.Int{}, &_py), &_py, e1) //    24.   y = CMOV(-y, y, e1)
	c.field.inv(&tv4, &tv4)                                     //    25.   x = x / tv4
	c.field.mul(&_px, &_px, &tv4)

	return c.affineToPoint(&_px, &_py)
}

var (
	decompressed256 = [65]byte{0x04}
	decompressed384 = [97]byte{0x04}
	decompressed521 = [133]byte{0x04}
)

func (c *curve[point]) affineToPoint(_px, _py *big.Int) point {
	var decompressed []byte

	byteLen := (c.field.bitLen() + 7) / 8
	switch byteLen {
	case 32:
		decompressed = decompressed256[:]
	case 48:
		decompressed = decompressed384[:]
	case 66:
		decompressed = decompressed521[:]
	}

	decompressed[0] = 0x04
	_px.FillBytes(decompressed[1 : 1+byteLen])
	_py.FillBytes(decompressed[1+byteLen:])

	p, err := c.NewPoint().SetBytes(decompressed)
	if err != nil {
		panic(err)
	}

	return p
}
