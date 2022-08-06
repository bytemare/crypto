// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package crypto exposes a prime-order elliptic curve groups with additional hash-to-curve operations.
package crypto

import (
	"github.com/bytemare/crypto/internal"
)

// Element represents an element on the curve of the prime-order group.
type Element struct {
	internal.Element
}

func newPoint(p internal.Element) *Element {
	return &Element{p}
}

func (e *Element) Base() *Element {
	return &Element{e.Element.Base()}
}

func (e *Element) Identity() *Element {
	return &Element{e.Element.Identity()}
}

// Add returns the sum of the Points, and does not change the receiver.
func (e *Element) Add(element *Element) *Element {
	if element == nil {
		return e
	}

	e.Element.Add(element.Element)

	return e
}

func (e *Element) Double() *Element {
	return &Element{e.Element.Double()}
}

func (e *Element) Negate() *Element {
	return &Element{e.Element.Negate()}
}

// Subtract returns the difference between the Points, and does not change the receiver.
func (e *Element) Subtract(element *Element) *Element {
	if element == nil {
		return &Element{e.Element.Copy()}
	}

	e.Element.Subtract(element.Element)

	return e
}

// Multiply returns the scalar multiplication of the receiver element with the given scalar.
func (e *Element) Multiply(scalar *Scalar) *Element {
	if scalar == nil {
		return &Element{e.Element.Identity()}
	}

	e.Element.Multiply(scalar.Scalar)

	return e
}

// Equal returns 1 if the elements are equivalent, and 0 otherwise.
func (e *Element) Equal(element *Element) int {
	if element == nil {
		return 0
	}

	return e.Element.Equal(element.Element)
}

// IsIdentity returns whether the element is the Group's identity element.
func (e *Element) IsIdentity() bool {
	return e.Element.IsIdentity()
}

// Copy returns a copy of the element.
func (e *Element) Copy() *Element {
	return &Element{e.Element.Copy()}
}

// Encode returns the compressed byte encoding of the element.
func (e *Element) Encode() []byte {
	return e.Element.Encode()
}

// Decode decodes the input and sets the current element to its value, and returns it.
func (e *Element) Decode(in []byte) error {
	return e.Element.Decode(in)
}

// MarshalBinary returns the compressed byte encoding of the element.
func (e *Element) MarshalBinary() ([]byte, error) {
	return e.Element.MarshalBinary()
}

// UnmarshalBinary sets e to the decoding of the byte encoded element.
func (e *Element) UnmarshalBinary(data []byte) error {
	return e.Element.UnmarshalBinary(data)
}

// MarshalText implements the encoding.MarshalText interface.
func (e *Element) MarshalText() (text []byte, err error) {
	return e.Element.MarshalText()
}

// UnmarshalText implements the encoding.UnmarshalText interface.
func (e *Element) UnmarshalText(text []byte) error {
	return e.Element.UnmarshalText(text)
}
