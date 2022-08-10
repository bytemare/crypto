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

// Scalar interface abstracts common operations on scalars in a prime-order Group.
type Scalar interface {
	// Zero sets the scalar to 0, and returns it.
	Zero() Scalar

	// One sets the scalar to 1, and returns it.
	One() Scalar

	// Random sets the current scalar to a new random scalar and returns it.
	// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
	Random() Scalar

	// Add set the receiver to the sum of the input to the receiver, and returns the receiver.
	Add(Scalar) Scalar

	// Subtract subtracts the input from the receiver, and returns the receiver.
	Subtract(Scalar) Scalar

	// Multiply multiplies the receiver with the input, and returns the receiver.
	Multiply(Scalar) Scalar

	// Invert set the receiver to the scalar's modular inverse ( 1 / scalar ), and returns it.
	Invert() Scalar

	// Equal returns 1 if the scalars are equal, and 0 otherwise.
	Equal(Scalar) int

	// IsZero returns whether the scalar is 0.
	IsZero() bool

	// Set sets the receiver to the argument, and returns the receiver.
	Set(Scalar) Scalar

	// Copy returns a copy of the receiver.
	Copy() Scalar

	// Encode returns the compressed byte encoding of the scalar.
	Encode() []byte

	// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
	Decode(in []byte) error

	// BinaryMarshaler returns a byte representation of the element.
	encoding.BinaryMarshaler

	// BinaryUnmarshaler recovers an element from a byte representation
	// produced either by encoding.BinaryMarshaler or MarshalBinaryCompress.
	encoding.BinaryUnmarshaler

	// TextMarshaler returns a base64 standard string encoding of the element.
	encoding.TextMarshaler

	// TextUnmarshaler sets the base64 standard string encoding of the element.
	encoding.TextUnmarshaler
}
