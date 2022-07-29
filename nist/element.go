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

// Add returns the sum of the Elements, and does not change the receiver.
func (e *Element[P]) Add(element internal.Element) internal.Element {
	ec := checkElement[P](element)

	return &Element[P]{
		p:   e.new().Add(e.p, ec.p),
		new: e.new,
	}
}

func (e *Element[Point]) negate() Point {
	enc := e.p.BytesCompressed()
	switch enc[0] {
	case 0x02:
		enc[0] = 0x03
	case 0x03:
		enc[0] = 0x02
	}

	neg := e.new()
	if _, err := neg.SetBytes(enc); err != nil {
		panic(err)
	}

	return neg
}

// Sub returns the difference between the Elements, and does not change the receiver.
func (e *Element[P]) Sub(element internal.Element) internal.Element {
	ec := checkElement[P](element).negate()

	return &Element[P]{
		p:   e.new().Add(e.p, ec),
		new: e.new,
	}
}

// Mult returns the scalar multiplication of the receiver element with the given scalar,
// and does not change the receiver.
func (e *Element[P]) Mult(scalar internal.Scalar) internal.Element {
	p := e.new()
	if _, err := p.ScalarMult(e.p, scalar.Bytes()); err != nil {
		panic(err)
	}

	return &Element[P]{
		p:   p,
		new: e.new,
	}
}

// IsIdentity returns whether the element is the Group's identity element.
func (e *Element[P]) IsIdentity() bool {
	b := e.p.BytesCompressed()
	i := e.new().BytesCompressed()

	return subtle.ConstantTimeCompare(b, i) == 1
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

// Bytes returns the compressed byte encoding of the element.
func (e *Element[P]) Bytes() []byte {
	return e.p.BytesCompressed()
}
