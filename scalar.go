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

// Scalar represents a scalar in the prime-order group.
type Scalar struct {
	internal.Scalar
}

func newScalar(s internal.Scalar) *Scalar {
	return &Scalar{s}
}

func (s *Scalar) Zero() *Scalar {
	s.Scalar.Zero()
	return s
}

func (s *Scalar) One() *Scalar {
	s.Scalar.One()
	return s
}

// Random sets the current scalar to a new random scalar and returns it.
func (s *Scalar) Random() *Scalar {
	s.Scalar.Random()
	return s
}

// Add returns the sum of the scalars, and does not change the receiver.
func (s *Scalar) Add(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s
	}

	s.Scalar.Add(scalar.Scalar)

	return s
}

// Subtract returns the difference between the scalars, and does not change the receiver.
func (s *Scalar) Subtract(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s
	}

	s.Scalar.Subtract(scalar.Scalar)

	return s
}

// Multiply returns the multiplication of the scalars, and does not change the receiver.
func (s *Scalar) Multiply(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s.Zero()
	}

	s.Scalar.Multiply(scalar.Scalar)

	return s
}

// Invert returns the scalar's modular inverse ( 1 / scalar ), and does not change the receiver.
func (s *Scalar) Invert() *Scalar {
	s.Scalar.Invert()
	return s
}

func (s *Scalar) Equal(scalar *Scalar) int {
	if scalar == nil {
		return 0
	}

	return s.Scalar.Equal(scalar.Scalar)
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.Scalar.IsZero()
}

// Copy returns a copy of the Scalar.
func (s *Scalar) Copy() *Scalar {
	return &Scalar{s.Scalar.Copy()}
}

// Encode returns the byte encoding of the element.
func (s *Scalar) Encode() []byte {
	return s.Scalar.Encode()
}

// Decode decodes the input and sets the current scalar to its value, and returns it.
func (s *Scalar) Decode(in []byte) error {
	return s.Scalar.Decode(in)
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.Scalar.MarshalBinary()
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	return s.Scalar.UnmarshalBinary(data)
}

// MarshalText implements the encoding.TextMarshaler interface.
func (s *Scalar) MarshalText() (text []byte, err error) {
	return s.Scalar.MarshalText()
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (s *Scalar) UnmarshalText(text []byte) error {
	return s.Scalar.UnmarshalText(text)
}
