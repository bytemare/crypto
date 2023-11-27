// SPDX-License-Identifier: MIT
//
// Copyright (C) 2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in theg
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package d448

import (
	"crypto/subtle"
	"encoding/hex"
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
	x, y, z, t big.Int
}

var identity = Element{
	x: *Fp.Zero(),
	y: *Fp.One(),
	z: *Fp.Zero(), // The Identity element is the only with z == 0
	t: *Fp.Zero(),
}

func newElementWithAffine(x, y *big.Int) *Element {
	e := &Element{
		x: big.Int{},
		y: big.Int{},
		z: big.Int{},
		t: big.Int{},
	}

	e.x.Set(x)
	e.y.Set(y)
	e.z.Set(scOne)
	Fp.Mul(&e.t, x, y)

	return e
}

// newElement returns a new element set to the point at infinity.
func newElement() *Element {
	e := &Element{
		x: big.Int{},
		y: big.Int{},
		z: big.Int{},
		t: big.Int{},
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

// affine returns the affine (x,y) coordinates from the inner projective representation.
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
	hexEncoded := "6666666666666666666666666666666666666666666666666666666633333333333333333333333333333333333333333333333333333333"
	encoded, _ := hex.DecodeString(hexEncoded)
	if err := e.Decode(encoded); err != nil {
		panic(err)
	}

	e.print()
	log.Printf("reencoded: %v", hex.EncodeToString(e.Encode()))

	e.x.Set(baseX)
	e.y.Set(baseY)
	e.z.Set(scOne)
	Fp.Mul(&e.t, &e.x, &e.y)

	return e
}

// Identity sets the element to the point at infinity of the Group's underlying curve.
func (e *Element) Identity() internal.Element {
	return e.set(&identity)
}

func (e *Element) setCoordinates(x, y, z, t *big.Int) {
	e.x.Set(x)
	e.y.Set(y)
	e.z.Set(z)
	e.t.Set(t)
}

func (e *Element) affineAdd(element *Element) internal.Element {
	var t0, t1, t2, t3, x, y big.Int

	Fp.Mul(&t0, d, &e.x)         // Dx1
	Fp.Mul(&t0, &t0, &e.y)       // Dx1y1
	Fp.Mul(&t0, &t0, &element.x) // Dx1y1x2
	Fp.Mul(&t0, &t0, &element.y) // Dx1y1x2y2
	Fp.Add(&t2, Fp.One(), &t0)   // 1+Dx1y1x2y2
	Fp.Sub(&t3, Fp.One(), &t0)   // 1-Dx1y1x2y2
	Fp.Inv(&t2, &t2)             // 1/(1+Dx1y1x2y2)
	Fp.Inv(&t3, &t3)             // 1/(1-Dx1y1x2y2)

	Fp.Mul(&t0, &e.x, &element.y) // x1y2
	Fp.Mul(&t1, &element.x, &e.y) // x2y1
	Fp.Add(&t0, &t0, &t1)         // x1y2+x2y1
	Fp.Mul(&x, &t0, &t2)          // (x1y2+x2y1)/(1+Dx1y1x2y2)

	Fp.Mul(&t0, &e.y, &element.y) // y1y2
	Fp.Mul(&t1, &e.x, &element.x) // x1x2
	//fp.Mul(&t1, &t1, fp.One())  // Ax1x2
	Fp.Sub(&t0, &t0, &t1) // y1y2-Ax1x2
	Fp.Mul(&y, &t0, &t3)  // (y1y2-Ax1x2)/(1-Dx1y1x2y2)

	e.x.Set(&x)
	e.y.Set(&y)
	Fp.Mul(&e.t, &x, &y)

	return e
}

func (e *Element) addProjectiveComplete(element *Element) internal.Element {
	var t0, t1, t2, t3, t4, x3, y3, z3 big.Int

	Fp.Mul(&t0, &e.x, &element.x) // t0 := X1 * X2
	Fp.Mul(&t1, &e.y, &element.y) // t1 := Y1 * Y2
	Fp.Mul(&t2, &e.z, &element.z) // t2 := Z1 * Z2

	Fp.Add(&t3, &e.x, &e.y)             // t3 := X1 + Y1
	Fp.Add(&t4, &element.x, &element.y) // t4 := X2 + Y2
	Fp.Mul(&t3, &t3, &t4)               // t3 := t3 * t4

	Fp.Add(&t4, &t0, &t1)   // t4 := t0 + t1
	Fp.Sub(&t3, &t3, &t4)   // t3 := t3 - t4
	Fp.Add(&t4, &e.y, &e.z) // t4 := Y1 + Z1

	Fp.Add(&x3, &element.y, &element.z) // X3 := Y2 + Z2
	Fp.Mul(&t4, &t4, &x3)               // t4 := t4 * X3
	Fp.Add(&x3, &t1, &t2)               // X3 := t1 + t2

	Fp.Sub(&t4, &t4, &x3)               // t4 := t4 - X3
	Fp.Add(&x3, &e.x, &e.z)             // X3 := X1 + Z1
	Fp.Add(&y3, &element.x, &element.z) // Y3 := X2 + Z2

	Fp.Mul(&x3, &x3, &y3) // X3 := X3 * Y3
	Fp.Add(&y3, &t0, &t2) // Y3 := t0 + t2
	Fp.Sub(&y3, &x3, &y3) // Y3 := X3 - Y3

	Fp.Add(&x3, &t0, &t0) // X3 := t0 + t0
	Fp.Add(&t0, &x3, &t0) // t0 := X3 + t0
	//fp.Mul(&t2, b3, &t2)  // t2 := b3 * t2

	Fp.Add(&z3, &t1, &t2) // Z3 := t1 + t2
	Fp.Sub(&t1, &t1, &t2) // t1 := t1 - t2
	//fp.Mul(&y3, b3, &y3)  // Y3 := b3 * Y3

	Fp.Mul(&x3, &t4, &y3) // X3 := t4 * Y3
	Fp.Mul(&t2, &t3, &t1) // t2 := t3 * t1
	Fp.Sub(&x3, &t2, &x3) // X3 := t2 - X3

	Fp.Mul(&y3, &y3, &t0) // Y3 := Y3 * t0
	Fp.Mul(&t1, &t1, &z3) // t1 := t1 * Z3
	Fp.Add(&y3, &t1, &y3) // Y3 := t1 + Y3

	Fp.Mul(&t0, &t0, &t3) // t0 := t0 * t3
	Fp.Mul(&z3, &z3, &t4) // Z3 := Z3 * t4
	Fp.Add(&z3, &z3, &t0) // Z3 := Z3 + t0

	Fp.Mul(&t3, &x3, &y3)

	// Don't use branches to check whether either one is the identity element. If none is, x3, y3, z3 are left as-is.
	ctSet(element.IsIdentity(), &x3, &e.x, &x3)
	ctSet(element.IsIdentity(), &y3, &e.y, &y3)
	ctSet(element.IsIdentity(), &z3, &e.z, &z3)
	ctSet(element.IsIdentity(), &t3, &e.t, &t3)

	ctSet(e.IsIdentity(), &x3, &element.x, &x3)
	ctSet(e.IsIdentity(), &y3, &element.y, &y3)
	ctSet(e.IsIdentity(), &z3, &element.z, &z3)
	ctSet(e.IsIdentity(), &t3, &element.z, &t3)

	e.setCoordinates(&x3, &y3, &z3, &t3)

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
	return Fp.IsZero(&e.y)
}

func (e *Element) affineDouble() internal.Element {
	return e.affineAdd(e)
}

func (e *Element) doubleProjectiveComplete() internal.Element {
	var t0, t1, t2, x3, y3, z3 big.Int

	Fp.Square(&t0, &e.y)  // t0 := Y ^2
	Fp.Add(&z3, &t0, &t0) // Z3 := t0 + t0
	Fp.Add(&z3, &z3, &z3) // Z3 := Z3 + Z3

	Fp.Add(&z3, &z3, &z3)   // Z3 := Z3 + Z3
	Fp.Mul(&t1, &e.y, &e.z) // t1 := Y * Z
	Fp.Square(&t2, &e.z)    // t2 := Z ^2

	//fp.Mul(&t2, b3, &t2)  // t2 := b3 * t2
	Fp.Mul(&x3, &t2, &z3) // X3 := t2 * Z3
	Fp.Add(&y3, &t0, &t2) // Y3 := t0 + t2

	Fp.Mul(&z3, &t1, &z3) // Z3 := t1 * Z3
	Fp.Add(&t1, &t2, &t2) // t1 := t2 + t2
	Fp.Add(&t2, &t1, &t2) // t2 := t1 + t2

	Fp.Sub(&t0, &t0, &t2) // t0 := t0 - t2
	Fp.Mul(&y3, &t0, &y3) // Y3 := t0 * Y3
	Fp.Add(&y3, &x3, &y3) // Y3 := X3 + Y3

	Fp.Mul(&t1, &e.x, &e.y) // t1 := X * Y
	Fp.Mul(&x3, &t0, &t1)   // X3 := t0 * t1
	Fp.Add(&x3, &x3, &x3)   // X3 := X3 + X3

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
	if Fp.AreEqual(&scalar.scalar, scOne) {
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

func (e *Element) print() {
	log.Printf("x: %s", hex.EncodeToString(e.x.Bytes()))
	log.Printf("y: %s", hex.EncodeToString(e.y.Bytes()))
	log.Printf("z: %s", hex.EncodeToString(e.z.Bytes()))
	log.Printf("t: %s", hex.EncodeToString(e.t.Bytes()))
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (e *Element) isEqual(element *Element) int {
	var t1, t2 big.Int

	e.print()
	element.print()

	Fp.Mul(&t1, &e.x, &element.y)
	Fp.Mul(&t2, &e.y, &element.x)

	var b1, b2 [elementLength]byte
	t1.FillBytes(b1[:])
	t2.FillBytes(b2[:])

	log.Printf("b1 : %v", hex.EncodeToString(b1[:]))
	log.Printf("b2 : %v", hex.EncodeToString(b2[:]))

	return subtle.ConstantTimeCompare(b1[:], b2[:])
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (e *Element) Equal(element internal.Element) int {
	q := assertElement(element)
	return e.isEqual(q)
}

// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
func (e *Element) IsIdentity() bool {
	return e.x.Sign() == 0 && e.y.Cmp(Fp.One()) == 0
}

func (e *Element) set(element *Element) *Element {
	e.x.Set(&element.x)
	e.y.Set(&element.y)
	e.z.Set(&element.z)
	e.t.Set(&element.t)

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

func reverse(u []byte) []byte {
	l := len(u)
	last := l - 1

	for i := 0; i < l/2; i++ {
		u[i], u[last-i] = u[last-i], u[i]
	}

	return u
}

// Encode returns the compressed byte encoding of the element.
func (e *Element) Encode() []byte {
	var output [elementLength]byte
	var u1, u2 big.Int

	Fp.Add(&u1, &e.x, &e.t)
	Fp.Sub(&u2, &e.x, &e.t)
	Fp.Mul(&u1, &u1, &u2) // u1 = (x0 + t0) * (x0 - t0)

	Fp.Square(&u2, &e.x)
	Fp.Mul(&u2, &u2, oneMinusD)
	Fp.Mul(&u2, &u2, &u1) // u1 * ONE_MINUS_D * x0²

	_, invSqrt := SqrtRatioM1(Fp.One(), &u2)

	Fp.Mul(&u2, invSqrt, &u1)
	Fp.Mul(&u2, &u2, sqrtMinusD)
	ratio := ctAbs(&u2) // ratio = CT_ABS(invsqrt * u1 * SQRT_MINUS_D)

	Fp.Mul(&u2, invSqrt, ratio)
	Fp.Mul(&u2, &u2, &e.z)
	Fp.Sub(&u2, &u2, &e.t) // u2 = INVSQRT_MINUS_D * ratio * z0 - t0

	Fp.Mul(&u1, oneMinusD, invSqrt)
	Fp.Mul(&u1, &u1, &e.x)
	Fp.Mul(&u1, &u1, &u2)
	s := ctAbs(&u1) // s = CT_ABS(ONE_MINUS_D * invsqrt * x0 * u2)

	s.FillBytes(output[:])

	return reverse(output[:])
}

// XCoordinate returns the encoded x coordinate of the element, which is the same as Encode().
func (e *Element) XCoordinate() []byte {
	return e.Encode()[:]
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (e *Element) Decode(data []byte) error {
	if len(data) != elementLength {
		return errParamInvalidPointEncoding
	}

	u := make([]byte, elementLength)
	copy(u, data)
	u = reverse(u[:])

	s := new(big.Int).SetBytes(u)
	isInOrder := s.Cmp(Fp.Order()) == -1
	isPositive := s.Sign() >= 0

	var ss, u1, u2, u3, t1, t2, x, y, t big.Int

	Fp.Square(&ss, s)          // ss = s²
	Fp.Add(&u1, Fp.One(), &ss) // u1 = 1 + ss
	Fp.Square(&t1, &u1)
	Fp.Mul(&t2, d4, &ss)
	Fp.Sub(&u2, &t1, &t2) // u2 = u1^2 - 4 * D * ss

	Fp.Mul(&t1, &u2, &t1)
	wasSquare, invSqrt := SqrtRatioM1(Fp.One(), &t1) // (was_square, invsqrt) = SQRT_RATIO_M1(1, u2 * u1^2)

	Fp.Lsh(&u3, s, 1) // 2 * s
	Fp.Mul(&u3, &u3, invSqrt)
	Fp.Mul(&u3, &u3, &u1)
	Fp.Mul(&u3, &u3, sqrtMinusD)
	ctAbs(&u3) // u3 = 2*s*invSqrt*u1*sqrtMinusD

	Fp.Mul(&x, &u3, invSqrt)
	Fp.Mul(&x, &x, &u2)
	Fp.Mul(&x, &x, invSqrtMinusD) // x = u3 * invSqrt * u2 * invSqrtMinusD

	Fp.Sub(&y, Fp.One(), &ss)
	Fp.Mul(&y, &y, invSqrt)
	Fp.Mul(&y, &y, &u1) // y = (1-s²)*invSqrt*u1

	Fp.Mul(&t, &x, &y)

	isOk := isInOrder && isPositive && wasSquare

	ctSet(isOk, &e.x, &x, &e.x)
	ctSet(isOk, &e.y, &y, &e.y)
	ctSet(isOk, &e.z, Fp.One(), &e.z)
	ctSet(isOk, &e.t, &t, &e.t)

	if !isOk {
		return errParamInvalidPointEncoding
	}

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
