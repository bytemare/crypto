// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist

import (
	"crypto/subtle"

	"github.com/bytemare/crypto/internal"
)

// Element implements the Element interface for group elements over NIST curves.
type Element[Point nistECPoint[Point]] struct {
	p   Point
	new func() Point
}

func checkElement[Point nistECPoint[Point]](element internal.Element) *Element[Point] {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ec, ok := element.(*Element[Point])
	if !ok {
		panic(internal.ErrCastElement)
	}

	return ec
}

func (e *Element[Point]) Base() internal.Element {
	e.p.SetGenerator()
	return e
}

func (e *Element[Point]) Identity() internal.Element {
	e.p = e.new()
	return e
}

// Add returns the sum of the Elements, and does not change the receiver.
func (e *Element[Point]) Add(element internal.Element) internal.Element {
	ec := checkElement[Point](element)
	e.p.Add(e.p, ec.p)

	return e
}

func (e *Element[Point]) Double() internal.Element {
	e.p.Double(e.p)
	return e
}

func (e *Element[Point]) negate() {
	enc := e.p.BytesCompressed()
	switch enc[0] {
	case 0x02:
		enc[0] = 0x03
	case 0x03:
		enc[0] = 0x02
	}

	if _, err := e.p.SetBytes(enc); err != nil {
		panic(err)
	}
}

// Negate returns the negative of the Element, and does not change the receiver.
func (e *Element[P]) Negate() internal.Element {
	e.negate()
	return e
}

// Subtract returns the difference between the Elements, and does not change the receiver.
func (e *Element[P]) Subtract(element internal.Element) internal.Element {
	ec := checkElement[P](element)
	ec.negate()
	e.p.Add(e.p, ec.p)

	return e
}

// Multiply returns the scalar multiplication of the receiver element with the given scalar,
// and does not change the receiver.
func (e *Element[P]) Multiply(scalar internal.Scalar) internal.Element {
	if _, err := e.p.ScalarMult(e.p, scalar.Encode()); err != nil {
		panic(err)
	}

	return e
}

func (e *Element[Point]) Equal(element internal.Element) int {
	ec := checkElement[Point](element)

	return subtle.ConstantTimeCompare(e.p.Bytes(), ec.p.Bytes())
}

// IsIdentity returns whether the element is the Group's identity element.
func (e *Element[P]) IsIdentity() bool {
	b := e.p.BytesCompressed()
	i := e.new().BytesCompressed()

	return subtle.ConstantTimeCompare(b, i) == 1
}

func (e *Element[P]) set(element *Element[P]) *Element[P] {
	*e = *element
	return e
}

// Set sets the receiver to the argument, and returns the receiver.
func (e *Element[P]) Set(element internal.Element) internal.Element {
	if element == nil {
		return e.set(nil)
	}

	ec, ok := element.(*Element[P])
	if !ok {
		panic(internal.ErrCastElement)
	}

	return e.set(ec)
}

// Copy returns a copy of the element.
func (e *Element[P]) Copy() internal.Element {
	return &Element[P]{
		p:   e.new().Set(e.p),
		new: e.new,
	}
}

// Decode sets p to the value of the decoded input, and returns p.
func (e *Element[P]) Decode(in []byte) (internal.Element, error) {
	p := e.new()
	if _, err := p.SetBytes(in); err != nil {
		return nil, err
	}

	return &Element[P]{
		p:   p,
		new: e.new,
	}, nil
}

// Encode returns the compressed byte encoding of the element.
func (e *Element[P]) Encode() []byte {
	return e.p.BytesCompressed()
}

// MarshalBinary returns the compressed byte encoding of the element.
func (e *Element[P]) MarshalBinary() ([]byte, error) {
	return e.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded element.
func (e *Element[P]) UnmarshalBinary(data []byte) error {
	_, err := e.Decode(data)
	return err
}
