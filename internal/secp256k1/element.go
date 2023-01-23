// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1

import (
	"fmt"
	"math/big"

	"github.com/bytemare/crypto/internal"
)

// Element implements the Element interface for the Secp256k1 group element.
type Element struct {
	x, y, z big.Int
}

var identity = Element{
	x: big.Int{},
	y: big.Int{},
	z: big.Int{}, // The Identity element is the only with z == 0
}

func newElementWithAffine(x, y *big.Int) *Element {
	e := &Element{
		x: big.Int{},
		y: big.Int{},
		z: *big.NewInt(1),
	}
	e.x.Set(x)
	e.y.Set(y)

	return e
}

// newElement returns a new element set to the point at infinity.
func newElement() *Element {
	e := &Element{
		x: big.Int{},
		y: big.Int{},
		z: big.Int{},
	}

	return e.set(&identity)
}

func assertElement(element internal.Element) *Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ec, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return ec
}

// Base sets the element to the group's base point a.k.a. canonical generator.
func (e *Element) Base() internal.Element {
	e.x.Set(baseX)
	e.y.Set(baseY)
	e.z.Set(scOne)

	return e
}

// Identity sets the element to the point at infinity of the Group's underlying curve.
func (e *Element) Identity() internal.Element {
	return e.set(&identity)
}

func (e *Element) addAffine(element *Element) *Element {
	var t0, t1, ll, x, y big.Int
	fp.Sub(&t0, &element.y, &e.y) // (y2-y1)
	fp.Sub(&t1, &element.x, &e.x) // (x2-x1)
	fp.Inv(&t1, &t1)              // 1/(x2-x1)
	fp.Mul(&ll, &t0, &t1)         // l = (y2-y1)/(x2-x1)

	fp.Square(&t0, &ll)         // l^2
	fp.Sub(&t0, &t0, &e.x)      // l^2-x1
	fp.Sub(&x, &t0, &element.x) // x' = l^2-x1-x2

	fp.Sub(&t0, &e.x, &x) // x1-x3
	fp.Mul(&t0, &t0, &ll) // l(x1-x3)
	fp.Sub(&y, &t0, &e.y) // y3 = l(x1-x3)-y1

	e.x.Set(&x)
	e.y.Set(&y)

	fmt.Printf("Add\n")
	fmt.Printf(".\t - x: %v\n", x.String())
	fmt.Printf(".\t - y: %v\n", y.String())

	return e
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (e *Element) Add(element internal.Element) internal.Element {
	q := assertElement(element)
	return e.addAffine(q)
}

func bl2007Double(x, y *big.Int) (x3, y3 *big.Int) {
	x3, y3 = new(big.Int), new(big.Int)
	var x2, y2, y4, s, s2, m, t, z3 big.Int

	// 1M + 5S + (7 - 1) add
	fp.Square(&x2, x)
	fp.Square(&y2, y)
	fp.Square(&y4, &y2)
	fp.Add(&s, x, &y2)
	fp.Square(&s, &s)
	fp.Sub(&s, &s, &x2)
	fp.Sub(&s, &s, &y4)
	fp.Mul(&s, &s, big.NewInt(2))
	fp.Mul(&m, &x2, big.NewInt(3))
	// fp.Add(&m, &m, a) // a = 0

	fp.Mul(&s2, &s, big.NewInt(2))
	fp.Square(&t, &m)
	fp.Sub(&t, &t, &s2)

	x3.Set(&t)
	fp.Mul(&y4, &y4, big.NewInt(8))
	fp.Sub(y3, &s, &t)
	fp.Mul(y3, y3, &m)
	fp.Sub(y3, y3, &y4)
	fp.Mul(&z3, y, big.NewInt(2))

	return jacobiToAffine(x3, y3, &z3)
}

func jacobiDouble(X, Y, Z *big.Int) (x3, y3 *big.Int) {
	x3, y3 = new(big.Int), new(big.Int)
	var t0, t1, t2, z3 big.Int
	// 2S + 7M + 8A
	fp.Square(&t0, Y)     // t0 := Y^2
	fp.Add(&z3, &t0, &t0) // Z3 := t0 + t0
	fp.Add(&z3, &z3, &z3) // Z3 := Z3 + Z3
	fp.Add(&z3, &z3, &z3) // Z3 := Z3 + Z3
	fp.Mul(&t1, Y, Z)     // t1 := Y * Z
	fp.Square(&t2, Z)     // t2 := Z ^2
	fp.Mul(&t2, &t2, b)   // t2 := b3 * t2
	fp.Mul(x3, &t2, &z3)  // X3 := t2 * Z3
	fp.Add(y3, &t0, &t2)  // Y3 := t0 + t2
	fp.Mul(&z3, &t1, &z3) // Z3 := t1 * Z3
	fp.Add(&t1, &t2, &t2) // t1 := t2 + t2
	fp.Add(&t1, &t1, &t2) // t2 := t1 + t2
	fp.Sub(&t0, &t0, &t2) // t0 := t0 - t2
	fp.Mul(y3, &t0, y3)   // Y3 := t0 * Y3
	fp.Add(y3, x3, y3)    // Y3 := X3 + Y3
	fp.Mul(&t1, X, Y)     // t1 := X * Y
	fp.Mul(x3, &t0, &t1)  // X3 := t0 * t1
	fp.Add(x3, x3, x3)    // X3 := X3 + X3

	return jacobiToAffine(x3, y3, &z3)
}

func djbDouble(x1, y1 *big.Int) (*big.Int, *big.Int) {
	var t0, t1, _l, ll, lll, x, y big.Int

	fp.Square(&t0, x1)
	fp.Mul(&t0, &t0, big.NewInt(3)) // 3x^2
	fp.Add(&t1, y1, y1)
	fp.Inv(&t1, &t1)      // 1/2y
	fp.Mul(&_l, &t0, &t1) // _l = (3x^2+2A)/(2y)
	fp.Square(&ll, &_l)   // ll = (3x^2+2A)^2/(2y)^2

	// x
	fp.Sub(&x, &ll, x1) // l^2-x
	fp.Sub(&x, &x, x1)  // x' = l^2-2x

	// y
	fp.Mul(&y, x1, big.NewInt(3)) // 3x
	fp.Mul(&y, &y, &_l)           // 3x._l
	fp.Mul(&lll, &_l, &ll)        // lll = _l^3
	fp.Sub(&y, &y, &lll)          // 3x._l.lll
	fp.Sub(&y, &y, y1)            // y = 3x8- lll

	fmt.Printf("djbDouble\n")
	fmt.Printf(".\t - x: %v\n", x.String())
	fmt.Printf(".\t - y: %v\n", y.String())

	return &x, &y
}

func h2cDouble(x1, y1 *big.Int) (*big.Int, *big.Int) {
	var t0, t1, ll, x, y big.Int
	fp.Square(&t0, x1)              // x^2
	fp.Mul(&t0, &t0, big.NewInt(3)) // 3x^2
	fp.Add(&t0, &t0, a)             // 3x^2+A, A = 0 so we could skip that
	fp.Add(&t1, y1, y1)             // 2y
	fp.Inv(&t1, &t1)                // 1/2y
	fp.Mul(&ll, &t0, &t1)           // l = (3x^2+2A)/(2y)

	fp.Square(&t0, &ll)  // l^2
	fp.Sub(&t0, &t0, x1) // l^2-x
	fp.Sub(&x, &t0, x1)  // x' = l^2-2x

	fp.Sub(&t0, x1, &x)   // x-x'
	fp.Mul(&t0, &t0, &ll) // l(x-x')
	fp.Sub(&y, &t0, y1)   // y3 = l(x-x')-y1

	fmt.Printf("h2cDouble\n")
	fmt.Printf(".\t - x: %v\n", x.String())
	fmt.Printf(".\t - y: %v\n", y.String())

	return &x, &y
}

func jacobiToAffine(x, y, z *big.Int) (x2, y2 *big.Int) {
	x2, y2 = new(big.Int), new(big.Int)

	var z2, z3 big.Int
	fp.Square(&z2, z)
	fp.Mul(&z3, &z2, z)

	fp.Inv(&z2, &z2)
	fp.Inv(&z3, &z3)

	fp.Mul(x2, x, &z2)
	fp.Mul(y2, y, &z3)

	return x, y
}

// Double sets the receiver to its double, and returns it.
func (e *Element) Double() internal.Element {
	x, y := jacobiDouble(&e.x, &e.y, scOne)

	fmt.Printf("Jacobi Double\n")
	fmt.Printf(".\t - x: %v\n", x.String())
	fmt.Printf(".\t - y: %v\n", y.String())

	x, y = bl2007Double(&e.x, &e.y)

	fmt.Printf("BL Double\n")
	fmt.Printf(".\t - x: %v\n", x.String())
	fmt.Printf(".\t - y: %v\n", y.String())

	djbDouble(&e.x, &e.y)
	h2cDouble(&e.x, &e.y)

	e.x.Set(x)
	e.y.Set(y)
	e.z.Set(scOne)

	return e
}

func (e *Element) negate() *Element {
	e.y.Neg(&e.y)
	return e
}

// Negate sets the receiver to its negation, and returns it.
func (e *Element) Negate() internal.Element {
	if e.IsIdentity() {
		return e
	}

	return e.negate()
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (e *Element) Subtract(element internal.Element) internal.Element {
	q := assertElement(element).negate()
	return e.addAffine(q)
}

// Multiply sets the receiver to the scalar multiplication of the receiver with the given Scalar, and returns it.
func (e *Element) Multiply(scalar internal.Scalar) internal.Element {
	s := assert(scalar)

	if fp.AreEqual(&s.scalar, scOne) {
		return e
	}

	r0 := newElement()
	r1 := e.copy()

	for i := s.scalar.BitLen() - 1; i >= 0; i-- {
		if s.scalar.Bit(i) == 0 {
			r1.addAffine(r0)
			r0.Double()
		} else {
			r0.addAffine(r1)
			r1.Double()
		}
	}

	return e.set(r0)
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (e *Element) isEqual(element *Element) int {
	x := e.x.Cmp(&element.x)
	y := e.y.Cmp(&element.y)

	if x == 0 && y == 0 {
		return 1
	}

	return 0
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (e *Element) Equal(element internal.Element) int {
	q := assertElement(element)
	return e.isEqual(q)
}

// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
func (e *Element) IsIdentity() bool {
	return e.x.Sign() == 0 && e.y.Sign() == 0
}

func (e *Element) set(element *Element) *Element {
	e.x.Set(&element.x)
	e.y.Set(&element.y)

	return e
}

// Set sets the receiver to the value of the argument, and returns the receiver.
func (e *Element) Set(element internal.Element) internal.Element {
	q := assertElement(element)
	return e.set(q)
}

func (e *Element) copy() *Element {
	return &Element{
		x: *new(big.Int).Set(&e.x),
		y: *new(big.Int).Set(&e.y),
		z: *new(big.Int).Set(&e.z),
	}
}

// Copy returns a copy of the receiver.
func (e *Element) Copy() internal.Element {
	return e.copy()
}

// Encode returns the compressed byte encoding of the element.
func (e *Element) Encode() []byte {
	if e.IsIdentity() {
		return []byte{0}
	}

	var output [elementLength]byte
	output[0] = 2 | e.y.Bytes()[0]&1
	e.x.FillBytes(output[1:])

	return output[:]
}

// XCoordinate returns the encoded x coordinate of the element, which is the same as Encode().
func (e *Element) XCoordinate() []byte {
	var compressed [elementLength]byte
	return e.x.FillBytes(compressed[1:])
}

// secp256Polynomial applies y^2=x^3+ax+b to recover y^2 from x.
func secp256Polynomial(y, x *big.Int) {
	fp.Mul(y, x, x)
	fp.Mul(y, y, x)
	fp.Add(y, y, b)
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (e *Element) Decode(data []byte) error {
	/*
		- check coordinates are in the correct range
		- check point is on the curve
		- point is not infinity
		- point order validation is not necessary since the cofactor is 1
	*/
	if len(data) != elementLength {
		return internal.ErrParamInvalidPointEncoding
	}

	if data[0] != 2 && data[0] != 3 {
		return internal.ErrParamInvalidPointEncoding
	}

	x := new(big.Int).SetBytes(data[1:])
	if x.Cmp(fp.Order()) != -1 {
		return internal.ErrParamInvalidPointEncoding
	}

	var y big.Int
	secp256Polynomial(&y, x)

	if !fp.IsSquare(&y) {
		return internal.ErrParamInvalidPointEncoding
	}

	fp.SquareRoot(&y, &y)

	cond := int(y.Bytes()[0]&1) ^ int(data[0]&1)
	fp.CondNeg(&y, &y, cond)

	// Identity Check
	if x.Cmp(scZero) == 0 && y.Cmp(scZero) == 0 {
		return internal.ErrIdentity
	}

	e.x.Set(x)
	e.y.Set(&y)

	return nil
}

// MarshalBinary returns the compressed byte encoding of the element.
func (e *Element) MarshalBinary() (data []byte, err error) {
	return e.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded element.
func (e *Element) UnmarshalBinary(data []byte) error {
	return e.Decode(data)
}
