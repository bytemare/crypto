// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal defines simple and abstract APIs to group Elements and Scalars.
package internal

// Element interface abstracts common operations on an Element in a prime-order Group.
type Element interface {
	// Add returns the sum of the Elements, and does not change the receiver.
	Add(Element) Element

	// Double returns the double of the element, and does not change the receiver.
	// Double(Element) Element

	// Sub returns the difference between the Elements, and does not change the receiver.
	Sub(Element) Element

	// Mult returns the scalar multiplication of the receiver with the given Scalar, and does not change the receiver.
	Mult(Scalar) Element

	// IsIdentity returns whether the Element is the point at infinity of the Group's underlying curve.
	IsIdentity() bool

	// Copy returns a copy of the Element.
	Copy() Element

	// Decode decodes the input a sets the receiver to its value, and returns it.
	Decode(in []byte) (Element, error)

	// Bytes returns the compressed byte encoding of the point.
	Bytes() []byte
}
