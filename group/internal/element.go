// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal defines simple and abstract APIs to group Elements and Scalars.
package internal

// Point interface abstracts common operations on Points in a Group.
type Point interface {
	// Add returns the sum of the Points, and does not change the receiver.
	Add(Point) Point

	// Sub returns the difference between the Points, and does not change the receiver.
	Sub(Point) Point

	// Mult returns the scalar multiplication of the receiver point with the given scalar.
	Mult(Scalar) Point

	// InvertMult returns the scalar multiplication of the receiver point with the inverse of the given scalar.
	InvertMult(Scalar) Point

	// IsIdentity returns whether the point is the Group's identity point.
	IsIdentity() bool

	// Copy returns a copy of the point.
	Copy() Point

	// Decode decodes the input an sets the current point to its value, and returns it.
	Decode(in []byte) (Point, error)

	// Bytes returns the compressed byte encoding of the point.
	Bytes() []byte
}
