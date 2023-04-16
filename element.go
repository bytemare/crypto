// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package crypto exposes a prime-order elliptic curve groups with additional hash-to-curve operations.
package crypto

import (
	"fmt"

	"github.com/bytemare/crypto/internal"
)

// Element represents an element on the curve of the prime-order group.
type Element struct {
	internal.Element
}

func newPoint(p internal.Element) *Element {
	return &Element{p}
}

// Base sets the element to the group's base point a.k.a. canonical generator.
func (e *Element) Base() *Element {
	return &Element{e.Element.Base()}
}

// Identity sets the element to the point at infinity of the Group's underlying curve.
func (e *Element) Identity() *Element {
	return &Element{e.Element.Identity()}
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (e *Element) Add(element *Element) *Element {
	if element == nil {
		return e
	}

	e.Element.Add(element.Element)

	return e
}

// Double sets the receiver to its double, and returns it.
func (e *Element) Double() *Element {
	e.Element.Double()
	return e
}

// Negate sets the receiver to its negation, and returns it.
func (e *Element) Negate() *Element {
	e.Element.Negate()
	return e
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (e *Element) Subtract(element *Element) *Element {
	if element == nil {
		return e
	}

	e.Element.Subtract(element.Element)

	return e
}

// Multiply sets the receiver to the scalar multiplication of the receiver with the given Scalar, and returns it.
func (e *Element) Multiply(scalar *Scalar) *Element {
	if scalar == nil {
		e.Element.Identity()
		return e
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

// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
func (e *Element) IsIdentity() bool {
	return e.Element.IsIdentity()
}

// Set sets the receiver to the argument, and returns the receiver.
func (e *Element) Set(element *Element) *Element {
	e.Element.Set(element.Element)
	return e
}

// Copy returns a copy of the receiver.
func (e *Element) Copy() *Element {
	return &Element{e.Element.Copy()}
}

// Encode returns the compressed byte encoding of the element.
func (e *Element) Encode() []byte {
	return e.Element.Encode()
}

// XCoordinate returns the encoded x coordinate of the element.
func (e *Element) XCoordinate() []byte {
	return e.Element.XCoordinate()
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (e *Element) Decode(data []byte) error {
	if err := e.Element.Decode(data); err != nil {
		return fmt.Errorf("element decoding: %w", err)
	}

	return nil
}

// MarshalBinary returns the compressed byte encoding of the element.
func (e *Element) MarshalBinary() ([]byte, error) {
	dec, err := e.Element.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("element MarshalBinary: %w", err)
	}

	return dec, nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded element.
func (e *Element) UnmarshalBinary(data []byte) error {
	if err := e.Element.UnmarshalBinary(data); err != nil {
		return fmt.Errorf("element UnmarshalBinary: %w", err)
	}

	return nil
}
