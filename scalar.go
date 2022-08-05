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

// Random sets the current scalar to a new random scalar and returns it.
func (s *Scalar) Random() *Scalar {
	s.Scalar.Random()
	return s
}

// Add returns the sum of the scalars, and does not change the receiver.
func (s *Scalar) Add(scalar *Scalar) *Scalar {
	if scalar == nil {
		return &Scalar{s.Scalar.Copy()}
	}

	return &Scalar{s.Scalar.Add(scalar.Scalar)}
}

// Sub returns the difference between the scalars, and does not change the receiver.
func (s *Scalar) Sub(scalar *Scalar) *Scalar {
	if scalar == nil {
		return &Scalar{s.Scalar.Copy()}
	}

	return &Scalar{s.Scalar.Subtract(scalar.Scalar)}
}

// Mult returns the multiplication of the scalars, and does not change the receiver.
func (s *Scalar) Mult(scalar *Scalar) *Scalar {
	if scalar == nil {
		s2 := Scalar{}
		return s2.Zero()
	}

	return &Scalar{s.Scalar.Multiply(scalar.Scalar)}
}

// Invert returns the scalar's modular inverse ( 1 / scalar ), and does not change the receiver.
func (s *Scalar) Invert() *Scalar {
	return &Scalar{s.Scalar.Invert()}
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

// Decode decodes the input an sets the current scalar to its value, and returns it.
func (s *Scalar) Decode(in []byte) (*Scalar, error) {
	q, err := s.Scalar.Decode(in)
	if err != nil {
		return nil, err
	}

	return &Scalar{q}, nil
}

// Bytes returns the byte encoding of the element.
func (s *Scalar) Bytes() []byte {
	return s.Scalar.Encode()
}

func (s *Scalar) Zero() *Scalar {
	s.Scalar.Zero()
	return s
}
