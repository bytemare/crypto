// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package edwards25519 wraps filippo.io/edwards25519 and exposes a simple prime-order group API with hash-to-curve.
package edwards25519

import (
	"filippo.io/edwards25519"

	"github.com/bytemare/crypto/internal"
)

const (
	inputLength             = 64
	canonicalEncodingLength = 32
)

// Scalar represents an Edwards25519 scalar.
// It wraps an Edwards25519 implementation to leverage its optimized operations.
type Scalar struct {
	scalar *edwards25519.Scalar
}

func assert(scalar internal.Scalar) *Scalar {
	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastScalar)
	}

	return sc
}

// Random sets the current scalar to a new random scalar and returns it.
func (s *Scalar) Random() internal.Scalar {
	for {
		_, err := s.scalar.SetUniformBytes(internal.RandomBytes(inputLength))
		if err != nil {
			panic(err)
		}

		if !s.IsZero() {
			return s
		}
	}
}

// Add returns the sum of the scalars, and does not change the receiver.
func (s *Scalar) Add(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := assert(scalar)
	s.scalar.Add(s.scalar, sc.scalar)

	return s
}

// Subtract returns the difference between the scalars, and does not change the receiver.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := assert(scalar)
	s.scalar.Subtract(s.scalar, sc.scalar)

	return s
}

// Multiply returns the multiplication of the scalars, and does not change the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := assert(scalar)
	s.scalar.Multiply(s.scalar, sc.scalar)

	return s
}

// Invert returns the scalar's modular inverse ( 1 / scalar ), and does not change the receiver.
func (s *Scalar) Invert() internal.Scalar {
	s.scalar.Invert(s.scalar)
	return s
}

func (s *Scalar) Equal(scalar internal.Scalar) int {
	if scalar == nil {
		return 0
	}

	sc := assert(scalar)

	return s.scalar.Equal(sc.scalar)
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.scalar.Equal(edwards25519.NewScalar()) == 1
}

func (s *Scalar) set(scalar *Scalar) *Scalar {
	*s = *scalar
	return s
}

// Set sets the receiver to the argument scalar, and returns the receiver.
func (s *Scalar) Set(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.set(nil)
	}

	sc := assert(scalar)

	return s.set(sc)
}

// Copy returns a copy of the Scalar.
func (s *Scalar) Copy() internal.Scalar {
	return &Scalar{edwards25519.NewScalar().Set(s.scalar)}
}

func decodeScalar(scalar []byte) (*edwards25519.Scalar, error) {
	if len(scalar) == 0 {
		return nil, internal.ErrParamNilScalar
	}

	if len(scalar) != canonicalEncodingLength {
		return nil, internal.ErrParamScalarLength
	}

	return edwards25519.NewScalar().SetCanonicalBytes(scalar)
}

// Decode decodes the input and sets the current scalar to its value, and returns it.
func (s *Scalar) Decode(in []byte) (internal.Scalar, error) {
	sc, err := decodeScalar(in)
	if err != nil {
		return nil, err
	}

	s.scalar = sc

	return s, nil
}

// Bytes returns the byte encoding of the element.
func (s *Scalar) Encode() []byte {
	return s.scalar.Bytes()
}

func (s *Scalar) Zero() internal.Scalar {
	s.scalar.Set(edwards25519.NewScalar())
	return s
}

// MarshalBinary returns the compressed byte encoding of the element.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded element.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	_, err := s.Decode(data)
	return err
}