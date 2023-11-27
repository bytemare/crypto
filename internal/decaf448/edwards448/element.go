// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in theg
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package edwards448

import (
	"errors"
	"github.com/bytemare/crypto/internal"
	"log"
	"math/big"
)

var (
	// errParamInvalidPointEncoding indicates an invalid point encoding has been provided.
	errParamInvalidPointEncoding = errors.New("invalid point encoding")

	// errIdentity indicates that the identity point (or point at infinity) has been encountered.
	errIdentity = errors.New("infinity/identity point")
)

// Element implements the Element interface for the Secp256k1 group element.
type Element struct {
	x, y, z big.Int
}

var identity = Element{
	x: *fp.Zero(),
	y: *fp.One(),
	z: *fp.Zero(), // The Identity element is the only with z == 0
}

func newElementWithAffine(x, y *big.Int) *Element {
	e := &Element{
		x: big.Int{},
		y: big.Int{},
		z: big.Int{},
	}

	e.x.Set(x)
	e.y.Set(y)
	e.z.Set(scOne)

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

// affine returns the affine (x,y) coordinates from the inner standard projective representation.
func (e *Element) affine() (x, y *big.Int) {
	//if e.z.Sign() == 0 {
	//	return fp.Zero(), fp.Zero()
	//}
	//
	//if fp.AreEqual(&e.z, scOne) {
	//	return &e.x, &e.y
	//}
	//
	//var zInv big.Int
	//x, y = new(big.Int), new(big.Int)
	//
	//fp.Inv(&zInv, &e.z)
	//fp.Mul(x, &e.x, &zInv)
	//fp.Mul(y, &e.y, &zInv)

	return &e.x, &e.y
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

func (e *Element) setCoordinates(x, y, z *big.Int) {
	e.x.Set(x)
	e.y.Set(y)
	e.z.Set(z)
}

func (e *Element) affineAdd(element *Element) internal.Element {
	var t0, t1, t2, t3, x, y big.Int

	fp.Mul(&t0, d, &e.x)         // Dx1
	fp.Mul(&t0, &t0, &e.y)       // Dx1y1
	fp.Mul(&t0, &t0, &element.x) // Dx1y1x2
	fp.Mul(&t0, &t0, &element.y) // Dx1y1x2y2
	fp.Add(&t2, fp.One(), &t0)   // 1+Dx1y1x2y2
	fp.Sub(&t3, fp.One(), &t0)   // 1-Dx1y1x2y2
	fp.Inv(&t2, &t2)             // 1/(1+Dx1y1x2y2)
	fp.Inv(&t3, &t3)             // 1/(1-Dx1y1x2y2)

	fp.Mul(&t0, &e.x, &element.y) // x1y2
	fp.Mul(&t1, &element.x, &e.y) // x2y1
	fp.Add(&t0, &t0, &t1)         // x1y2+x2y1
	fp.Mul(&x, &t0, &t2)          // (x1y2+x2y1)/(1+Dx1y1x2y2)

	fp.Mul(&t0, &e.y, &element.y) // y1y2
	fp.Mul(&t1, &e.x, &element.x) // x1x2
	//fp.Mul(&t1, &t1, fp.One())  // Ax1x2
	fp.Sub(&t0, &t0, &t1) // y1y2-Ax1x2
	fp.Mul(&y, &t0, &t3)  // (y1y2-Ax1x2)/(1-Dx1y1x2y2)

	e.x.Set(&x)
	e.y.Set(&y)

	return e
}

func (e *Element) addProjectiveComplete(element *Element) internal.Element {
	var t0, t1, t2, t3, t4, x3, y3, z3 big.Int

	fp.Mul(&t0, &e.x, &element.x) // t0 := X1 * X2
	fp.Mul(&t1, &e.y, &element.y) // t1 := Y1 * Y2
	fp.Mul(&t2, &e.z, &element.z) // t2 := Z1 * Z2

	fp.Add(&t3, &e.x, &e.y)             // t3 := X1 + Y1
	fp.Add(&t4, &element.x, &element.y) // t4 := X2 + Y2
	fp.Mul(&t3, &t3, &t4)               // t3 := t3 * t4

	fp.Add(&t4, &t0, &t1)   // t4 := t0 + t1
	fp.Sub(&t3, &t3, &t4)   // t3 := t3 - t4
	fp.Add(&t4, &e.y, &e.z) // t4 := Y1 + Z1

	fp.Add(&x3, &element.y, &element.z) // X3 := Y2 + Z2
	fp.Mul(&t4, &t4, &x3)               // t4 := t4 * X3
	fp.Add(&x3, &t1, &t2)               // X3 := t1 + t2

	fp.Sub(&t4, &t4, &x3)               // t4 := t4 - X3
	fp.Add(&x3, &e.x, &e.z)             // X3 := X1 + Z1
	fp.Add(&y3, &element.x, &element.z) // Y3 := X2 + Z2

	fp.Mul(&x3, &x3, &y3) // X3 := X3 * Y3
	fp.Add(&y3, &t0, &t2) // Y3 := t0 + t2
	fp.Sub(&y3, &x3, &y3) // Y3 := X3 - Y3

	fp.Add(&x3, &t0, &t0) // X3 := t0 + t0
	fp.Add(&t0, &x3, &t0) // t0 := X3 + t0
	//fp.Mul(&t2, b3, &t2)  // t2 := b3 * t2

	fp.Add(&z3, &t1, &t2) // Z3 := t1 + t2
	fp.Sub(&t1, &t1, &t2) // t1 := t1 - t2
	//fp.Mul(&y3, b3, &y3)  // Y3 := b3 * Y3

	fp.Mul(&x3, &t4, &y3) // X3 := t4 * Y3
	fp.Mul(&t2, &t3, &t1) // t2 := t3 * t1
	fp.Sub(&x3, &t2, &x3) // X3 := t2 - X3

	fp.Mul(&y3, &y3, &t0) // Y3 := Y3 * t0
	fp.Mul(&t1, &t1, &z3) // t1 := t1 * Z3
	fp.Add(&y3, &t1, &y3) // Y3 := t1 + Y3

	fp.Mul(&t0, &t0, &t3) // t0 := t0 * t3
	fp.Mul(&z3, &z3, &t4) // Z3 := Z3 * t4
	fp.Add(&z3, &z3, &t0) // Z3 := Z3 + t0

	switch {
	case element.IsIdentity():
		e.setCoordinates(&e.x, &e.y, &e.z)
	case e.IsIdentity():
		e.setCoordinates(&element.x, &element.y, &element.z)
	default:
		e.setCoordinates(&x3, &y3, &z3)
	}

	return e
}

func (e *Element) add(element *Element) internal.Element {
	//return e.addProjectiveComplete(element)
	return e.affineAdd(element)
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (e *Element) Add(element internal.Element) internal.Element {
	q := assertElement(element)
	return e.add(q)
}

func (e *Element) isTwoTorsion() bool {
	return fp.IsZero(&e.y)
}

func (e *Element) affineDouble() internal.Element {
	return e.affineAdd(e)
}

func (e *Element) doubleProjectiveComplete() internal.Element {
	var t0, t1, t2, x3, y3, z3 big.Int

	fp.Square(&t0, &e.y)  // t0 := Y ^2
	fp.Add(&z3, &t0, &t0) // Z3 := t0 + t0
	fp.Add(&z3, &z3, &z3) // Z3 := Z3 + Z3

	fp.Add(&z3, &z3, &z3)   // Z3 := Z3 + Z3
	fp.Mul(&t1, &e.y, &e.z) // t1 := Y * Z
	fp.Square(&t2, &e.z)    // t2 := Z ^2

	//fp.Mul(&t2, b3, &t2)  // t2 := b3 * t2
	fp.Mul(&x3, &t2, &z3) // X3 := t2 * Z3
	fp.Add(&y3, &t0, &t2) // Y3 := t0 + t2

	fp.Mul(&z3, &t1, &z3) // Z3 := t1 * Z3
	fp.Add(&t1, &t2, &t2) // t1 := t2 + t2
	fp.Add(&t2, &t1, &t2) // t2 := t1 + t2

	fp.Sub(&t0, &t0, &t2) // t0 := t0 - t2
	fp.Mul(&y3, &t0, &y3) // Y3 := t0 * Y3
	fp.Add(&y3, &x3, &y3) // Y3 := X3 + Y3

	fp.Mul(&t1, &e.x, &e.y) // t1 := X * Y
	fp.Mul(&x3, &t0, &t1)   // X3 := t0 * t1
	fp.Add(&x3, &x3, &x3)   // X3 := X3 + X3

	e.x.Set(&x3)
	e.y.Set(&y3)
	e.z.Set(&z3)

	return e
}

// Double sets the receiver to its double, and returns it.
func (e *Element) Double() internal.Element {
	//return e.doubleProjectiveComplete()
	return e.affineDouble()
}

func (e *Element) negate() *Element {
	e.x.Neg(&e.x)
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
	q := assertElement(element).copy().negate()
	return e.add(q)
}

/*
func cswap(condition bool, x0, x1 *big.Int) (*big.Int, *big.Int) {
	var b, x0b, x1b [56]byte // todo: find max size
	x0.FillBytes(x0b[:])
	x1.FillBytes(x1b[:])

	// todo: predefine arrays of only 1 and 0 for the condition
	x0.Xor()

}
*/

func (e *Element) montgomeryLadder(scalar *Scalar) internal.Element {
	//x0 := e.copy().doubleProjectiveComplete()
	x0 := e.copy().affineDouble()
	x1 := e.copy()

	for i := scalar.scalar.BitLen() - 1; i >= 0; i-- {
		if scalar.scalar.Bit(i) == 0 {
			x1.Add(x0)
			x0.Double()
		} else {
			x0.Add(x1)
			x1.Double()
		}
	}

	return e.Set(x0)
}

func (e *Element) multiply(scalar *Scalar) internal.Element {
	if fp.AreEqual(&scalar.scalar, scOne) {
		return e
	}

	r0 := newElement()
	r1 := e.copy()

	for i := scalar.scalar.BitLen() - 1; i >= 0; i-- {
		if scalar.scalar.Bit(i) == 0 {
			r1.Add(r0)
			r0.Double()
		} else {
			r0.Add(r1)
			r1.Double()
		}
	}

	return e.Set(r0)
}

// Multiply sets the receiver to the scalar multiplication of the receiver with the given Scalar, and returns it.
func (e *Element) Multiply(scalar internal.Scalar) internal.Element {
	s := assert(scalar)
	return e.multiply(s)
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (e *Element) isEqual(element *Element) int {
	x1, y1 := e.affine()
	x2, y2 := element.affine()
	x := x1.Cmp(x2)
	y := y1.Cmp(y2)

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
	return e.x.Sign() == 0 && e.y.Cmp(fp.One()) == 0
}

func (e *Element) set(element *Element) *Element {
	e.x.Set(&element.x)
	e.y.Set(&element.y)
	e.z.Set(&element.z)

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
	var output [elementLength]byte

	e.x.Sign()

	output[0] = byte(e.x.Bit(0))
	e.y.FillBytes(output[1:])

	return output[:]
}

// XCoordinate returns the encoded x coordinate of the element, which is the same as Encode().
func (e *Element) XCoordinate() []byte {
	return e.Encode()[1:]
}

func isOnCurve(x, y *big.Int) bool {
	var t0, t1, t2 big.Int

	fp.Square(&t0, x)          // x^2
	fp.Square(&t1, y)          // y^2
	fp.Mul(&t2, &t0, &t1)      // x^2y^2
	fp.Mul(&t2, &t2, d)        // Dx^2y^2
	fp.Add(&t2, &t2, fp.One()) // 1+Dx^2y^2
	//fp.Mul(&t0, &t0, fp.One()) // Ax^2
	fp.Add(&t0, &t0, &t1) // Ax^2+y^2

	return fp.AreEqual(&t0, &t1)
}

func polyToX2(x2, y *big.Int) {
	var t1, t2 big.Int

	fp.Square(&t1, y)
	fp.Sub(&t2, fp.One(), &t1)
	fp.Mul(&t1, &t1, d)
	fp.Sub(&t1, fp.One(), &t1)
	fp.Inv(&t1, &t1)
	fp.Mul(x2, &t1, &t2)
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (e *Element) Decode(data []byte) error {
	/*
		- check coordinates are in the correct range
		- check point is on the curve
		- point is not infinity
	*/
	if len(data) != elementLength {
		log.Printf("length")
		return errParamInvalidPointEncoding
	}

	if data[0] != 0 && data[0] != 1 {
		log.Printf("header")
		return errParamInvalidPointEncoding
	}

	y := new(big.Int).SetBytes(data[1:])
	if y.Cmp(fp.Order()) != -1 {
		log.Printf("order")
		return errParamInvalidPointEncoding
	}

	var x big.Int
	polyToX2(&x, y)

	if !fp.IsSquare(&x) {
		log.Printf("not square")
		return errParamInvalidPointEncoding
	}

	fp.SquareRoot(&x, &x)

	cond := int(x.Bit(0)&1) ^ int(data[0]&1)
	fp.CondNeg(&x, &x, cond)

	// Identity Check
	if x.Cmp(scZero) == 0 && y.Cmp(scZero) == 0 {
		return errIdentity
	}

	// Point order validation: TODO

	e.x.Set(&x)
	e.y.Set(y)
	e.z.Set(scOne)

	return nil
}

// MarshalBinary returns the compressed byte encoding of the element.
func (e *Element) MarshalBinary() ([]byte, error) {
	return e.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded element.
func (e *Element) UnmarshalBinary(data []byte) error {
	return e.Decode(data)
}
