// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal defines simple and abstract APIs to group Elements and Scalars.
package internal

// Scalar interface abstracts common operations on scalars in a prime-order Group.
type Scalar interface {
	// Random sets the current scalar to a new random scalar and returns it. The random source is crypto/rand, and this
	// functions is guaranteed to return a non-zero scalar.
	Random() Scalar

	// Add returns the sum of the scalars, and does not change the receiver.
	Add(scalar Scalar) Scalar

	// Subtract returns the difference between the scalars, and does not change the receiver.
	Subtract(scalar Scalar) Scalar

	// Multiply returns the multiplication of the scalars, and does not change the receiver.
	Multiply(scalar Scalar) Scalar

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

	// Equal returns 1 if the scalars are equal, and 0 otherwise.
	Equal(scalar Scalar) int

	// Zero sets the scalar to 0, and returns it.
	Zero() Scalar
}
