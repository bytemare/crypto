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
	"math/big"

	"github.com/bytemare/crypto/internal"
)

// Scalar represents a scalar in the prime-order group.
type Scalar struct {
	internal.Scalar
}

func newScalar(s internal.Scalar) *Scalar {
	return &Scalar{s}
}

// Zero sets the scalar to 0, and returns it.
func (s *Scalar) Zero() *Scalar {
	s.Scalar.Zero()
	return s
}

// One sets the scalar to 1, and returns it.
func (s *Scalar) One() *Scalar {
	s.Scalar.One()
	return s
}

// Random sets the current scalar to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() *Scalar {
	s.Scalar.Random()
	return s
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (s *Scalar) Add(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s
	}

	s.Scalar.Add(scalar.Scalar)

	return s
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (s *Scalar) Subtract(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s
	}

	s.Scalar.Subtract(scalar.Scalar)

	return s
}

// Multiply multiplies the receiver with the input, and returns the receiver.
func (s *Scalar) Multiply(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s.Zero()
	}

	s.Scalar.Multiply(scalar.Scalar)

	return s
}

// Pow sets s to s**scalar modulo the group order, and returns s. If scalar is nil, it returns 1.
func (s *Scalar) Pow(scalar *Scalar) *Scalar {
	if scalar == nil {
		return s.One()
	}

	s.Scalar.Pow(scalar.Scalar)

	return s
}

// Invert sets the receiver to the scalar's modular inverse ( 1 / scalar ), and returns it.
func (s *Scalar) Invert() *Scalar {
	s.Scalar.Invert()
	return s
}

// Equal returns 1 if the scalars are equal, and 0 otherwise.
func (s *Scalar) Equal(scalar *Scalar) int {
	if scalar == nil {
		return 0
	}

	return s.Scalar.Equal(scalar.Scalar)
}

// LessOrEqual returns 1 if s <= scalar, and 0 otherwise.
func (s *Scalar) LessOrEqual(scalar *Scalar) int {
	if scalar == nil {
		return 0
	}

	return s.Scalar.LessOrEqual(scalar.Scalar)
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.Scalar.IsZero()
}

// Set sets the receiver to the value of the argument scalar, and returns the receiver.
func (s *Scalar) Set(scalar *Scalar) *Scalar {
	s.Scalar.Set(scalar.Scalar)
	return s
}

// SetInt sets s to i modulo the field order, and returns an error if one occurs.
func (s *Scalar) SetInt(i *big.Int) error {
	if err := s.Scalar.SetInt(i); err != nil {
		return fmt.Errorf("scalar: %w", err)
	}

	return nil
}

// Copy returns a copy of the receiver.
func (s *Scalar) Copy() *Scalar {
	return &Scalar{s.Scalar.Copy()}
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	return s.Scalar.Encode()
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (s *Scalar) Decode(data []byte) error {
	if err := s.Scalar.Decode(data); err != nil {
		return fmt.Errorf("scalar Decode: %w", err)
	}

	return nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	dec, err := s.Scalar.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("scalar MarshalBinary: %w", err)
	}

	return dec, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	if err := s.Scalar.UnmarshalBinary(data); err != nil {
		return fmt.Errorf("scalar UnmarshalBinary: %w", err)
	}

	return nil
}
