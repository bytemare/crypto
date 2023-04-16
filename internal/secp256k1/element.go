// SPDX-License-Identifier: MIT
//
// Copyright (C)2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in theg
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1

import (
	"math/big"

	"github.com/bytemare/crypto/internal"
)

type mode uint8

const (
	incomplete mode = 1
	complete   mode = 2

	formulaType = incomplete
)

// Element implements the Element interface for the Secp256k1 group element.
type Element struct {
	x, y, z big.Int
}

var identity = Element{
	x: *fp.Zero(),
	y: *fp.Zero(),
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
	e.z.Set(fp.One())

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

func (e *Element) affine() (x, y *big.Int) {
	if e.z.Sign() == 0 {
		return fp.Zero(), fp.Zero()
	}

	if fp.AreEqual(&e.z, fp.One()) {
		return &e.x, &e.y
	}

	var zInv, zInvSq big.Int

	fp.Inv(&zInv, &e.z)
	fp.Square(&zInvSq, &zInv)

	x = new(big.Int)
	fp.Mul(x, &e.x, &zInvSq)
	fp.Mul(&zInvSq, &zInvSq, &zInv)

	y = new(big.Int)
	fp.Mul(y, &e.y, &zInvSq)

	return x, y
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
	x1, y1 := e.affine()
	x2, y2 := element.affine()

	fp.Sub(&t0, y2, y1)   // (y2-y1)
	fp.Sub(&t1, x2, x1)   // (x2-x1)
	fp.Inv(&t1, &t1)      // 1/(x2-x1)
	fp.Mul(&ll, &t0, &t1) // l = (y2-y1)/(x2-x1)

	fp.Square(&t0, &ll)  // l^2
	fp.Sub(&t0, &t0, x1) // l^2-x1
	fp.Sub(&x, &t0, x2)  // x' = l^2-x1-x2

	fp.Sub(&t0, x1, &x)   // x1-x3
	fp.Mul(&t0, &t0, &ll) // l(x1-x3)
	fp.Sub(&y, &t0, y1)   // y3 = l(x1-x3)-y1

	e.x.Set(&x)
	e.y.Set(&y)
	e.z.Set(fp.One())

	return e
}

// From http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl.
func (e *Element) addJacobianIncomplete(element *Element) *Element {
	var u1, u2, h, i, j, s1, s2, r, v, z1z1, z2z2, x3, y3, z3 big.Int

	fp.Square(&z1z1, &e.z)       // Z1Z1 = Z12
	fp.Square(&z2z2, &element.z) // Z2Z2 = Z22

	fp.Mul(&u1, &e.x, &z2z2)       // U1 = X1*Z2Z2
	fp.Mul(&u2, &element.x, &z1z1) // U2 = X2*Z1Z1
	fp.Sub(&h, &u2, &u1)           // H = U2-U1
	fp.Lsh(&i, &h, 1)              // I = (2*H)2
	fp.Square(&i, &i)              //
	fp.Mul(&j, &h, &i)             // J = H*I

	fp.Mul(&s1, &e.y, &element.z)
	fp.Mul(&s1, &s1, &z2z2) // S1 = Y1*Z2*Z2Z2
	fp.Mul(&s2, &element.y, &e.z)
	fp.Mul(&s2, &s2, &z1z1) // S2 = Y2*Z1*Z1Z1
	fp.Sub(&r, &s2, &s1)    // r = 2*(S2-S1)
	fp.Lsh(&r, &r, 1)
	fp.Mul(&v, &u1, &i) // V = U1*I

	x3.Set(&r)
	fp.Square(&x3, &x3)
	fp.Sub(&x3, &x3, &j)
	fp.Sub(&x3, &x3, &v)
	fp.Sub(&x3, &x3, &v) // X3 = r2-J-2*V

	y3.Set(&r)
	fp.Sub(&v, &v, &x3)
	fp.Mul(&y3, &y3, &v)
	fp.Mul(&s1, &s1, &j) // S1 = Y1*Z2*Z2Z2
	fp.Lsh(&s1, &s1, 1)
	fp.Sub(&y3, &y3, &s1) // Y3 = r*(V-X3)-2*S1*J

	fp.Add(&z3, &e.z, &element.z)
	fp.Square(&z3, &z3)
	fp.Sub(&z3, &z3, &z1z1)
	fp.Sub(&z3, &z3, &z2z2)
	fp.Mul(&z3, &z3, &h) // Z3 = ((Z1+Z2)2-Z1Z1-Z2Z2)*H

	e.x.Set(&x3)
	e.y.Set(&y3)
	e.z.Set(&z3)

	return e
}

// https://eprint.iacr.org/2015/1060.pdf
func (e *Element) addJacobianComplete(element *Element) *Element {
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
	fp.Mul(&t2, b3, &t2)  // t2 := b3 * t2

	fp.Add(&z3, &t1, &t2) // Z3 := t1 + t2
	fp.Sub(&t1, &t1, &t2) // t1 := t1 - t2
	fp.Mul(&y3, b3, &y3)  // Y3 := b3 * Y3

	fp.Mul(&x3, &t4, &y3) // X3 := t4 * Y3
	fp.Mul(&t2, &t3, &t1) // t2 := t3 * t1
	fp.Sub(&x3, &t2, &x3) // X3 := t2 - X3

	fp.Mul(&y3, &y3, &t0) // Y3 := Y3 * t0
	fp.Mul(&t1, &t1, &z3) // t1 := t1 * Z3
	fp.Add(&y3, &t1, &y3) // Y3 := t1 + Y3

	fp.Mul(&t0, &t0, &t3) // t0 := t0 * t3
	fp.Mul(&z3, &z3, &t4) // Z3 := Z3 * t4
	fp.Add(&z3, &z3, &t0) // Z3 := Z3 + t0

	e.x.Set(&x3)
	e.y.Set(&y3)
	e.z.Set(&z3)

	return e
}

func (e *Element) add(element *Element) *Element {
	if element.IsIdentity() {
		return e
	}

	if e.IsIdentity() {
		e.set(element)
		return e
	}

	if e.isEqual(element) == 1 {
		return e.double()
	}

	switch formulaType {
	case incomplete:
		return e.addJacobianIncomplete(element)
	case complete:
		return e.addJacobianComplete(element)
	}

	panic("invalid formula type")
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (e *Element) Add(element internal.Element) internal.Element {
	q := assertElement(element)
	return e.add(q)
}

// Double sets the receiver to its double, and returns it.
// From http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l.
func (e *Element) doubleJacobianIncomplete() *Element {
	var a, _b, c, d, e2, f, x3, y3, z3 big.Int

	fp.Square(&a, &e.x)
	fp.Square(&_b, &e.y)
	fp.Square(&c, &_b)

	fp.Add(&d, &e.x, &_b)
	fp.Square(&d, &d)
	fp.Sub(&d, &d, &a)
	fp.Sub(&d, &d, &c)
	fp.Lsh(&d, &d, 1)

	fp.Mul(&e2, &a, big.NewInt(3))
	fp.Square(&f, &e2)

	fp.Lsh(&x3, &d, 1)
	fp.Sub(&x3, &f, &x3)

	fp.Sub(&y3, &d, &x3)
	fp.Mul(&y3, &e2, &y3)
	fp.Lsh(&c, &c, 3)
	fp.Sub(&y3, &y3, &c)

	fp.Mul(&z3, &e.y, &e.z)
	fp.Lsh(&z3, &z3, 1)

	e.x.Set(&x3)
	e.y.Set(&y3)
	e.z.Set(&z3)

	return e
}

// https://eprint.iacr.org/2015/1060.pdf
func (e *Element) doubleJacobianComplete() *Element {
	var t0, t1, t2, x3, y3, z3 big.Int

	fp.Square(&t0, &e.y)  // t0 := Y ^2
	fp.Add(&z3, &t0, &t0) // Z3 := t0 + t0
	fp.Add(&z3, &z3, &z3) // Z3 := Z3 + Z3

	fp.Add(&z3, &z3, &z3)   // Z3 := Z3 + Z3
	fp.Mul(&t1, &e.y, &e.z) // t1 := Y * Z
	fp.Square(&t2, &e.z)    // t2 := Z ^2

	fp.Mul(&t2, b3, &t2)  // t2 := b3 * t2
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

func (e *Element) double() *Element {
	switch formulaType {
	case incomplete:
		return e.doubleJacobianIncomplete()
	case complete:
		return e.doubleJacobianComplete()
	}

	panic("invalid formula type")
}

// Double sets the receiver to its double, and returns it.
// From https://www.microsoft.com/en-us/research/wp-content/uploads/2016/06/complete-2.pdf.
func (e *Element) Double() internal.Element {
	return e.double()
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
	return e.addJacobianIncomplete(q)
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
			r1.add(r0)
			r0.double()
		} else {
			r0.add(r1)
			r1.double()
		}
	}

	return e.set(r0)
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
	return e.z.Sign() == 0 || e.x.Sign() == 0 && e.y.Sign() == 0
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

	if e.IsIdentity() {
		return output[:]
	}

	x, y := e.affine()
	output[0] = byte(2 | y.Bit(0)&1)
	x.FillBytes(output[1:])

	return output[:]
}

// XCoordinate returns the encoded x coordinate of the element, which is the same as Encode().
func (e *Element) XCoordinate() []byte {
	return e.Encode()[1:]
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
