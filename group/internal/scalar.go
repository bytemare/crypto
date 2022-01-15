// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal defines simple and abstract APIs to group Elements and Scalars.
package internal

// Scalar interface abstracts common operations on scalars in a Group.
type Scalar interface {
	// Random sets the current scalar to a new random scalar and returns it.
	Random() Scalar

	// Add returns the sum of the scalars, and does not change the receiver.
	Add(scalar Scalar) Scalar

	// Sub returns the difference between the scalars, and does not change the receiver.
	Sub(scalar Scalar) Scalar

	// Mult returns the multiplication of the scalars, and does not change the receiver.
	Mult(scalar Scalar) Scalar

	// Invert returns the scalar's modular inverse ( 1 / scalar ), and does not change the receiver.
	Invert() Scalar

	// IsZero returns whether the scalar is 0.
	IsZero() bool

	// Copy returns a copy of the Scalar.
	Copy() Scalar

	// Decode decodes the input an sets the current scalar to its value, and returns it.
	Decode(in []byte) (Scalar, error)

	// Bytes returns the byte encoding of the element.
	Bytes() []byte
}
