// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal defines simple and abstract APIs to group Elements and Scalars.
package internal

import "encoding"

// Element interface abstracts common operations on an Element in a prime-order Group.
type Element interface {
	// Base sets the element to the group's base point a.k.a. canonical generator.
	Base() Element

	// Identity sets the element to the point at infinity of the Group's underlying curve.
	Identity() Element

	// Add returns the sum of the Elements, and does not change the receiver.
	Add(Element) Element

	// Double returns the double of the element, and does not change the receiver.
	Double() Element

	// Negate returns the negative of the Element, and does not change the receiver.
	Negate() Element

	// Subtract returns the difference between the Elements, and does not change the receiver.
	Subtract(Element) Element

	// Multiply returns the scalar multiplication of the receiver with the given Scalar,
	// and does not change the receiver.
	Multiply(Scalar) Element

	// Equal returns 1 if the elements are equivalent, and 0 otherwise.
	Equal(element Element) int

	// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
	IsIdentity() bool

	// Set sets the receiver to the argument, and returns the receiver.
	Set(Element) Element

	// Copy returns a copy of the Element.
	Copy() Element

	// Encode returns the compressed byte encoding of the point.
	Encode() []byte

	// Decode decodes the input a sets the receiver to its value, and returns it.
	Decode(in []byte) error

	// BinaryMarshaler implementation.
	encoding.BinaryMarshaler

	// BinaryUnmarshaler implementation.
	encoding.BinaryUnmarshaler

	// TextMarshaler implementation.
	encoding.TextMarshaler

	// TextUnmarshaler implementation.
	encoding.TextUnmarshaler
}
