// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ristretto allows simple and abstracted operations in the Ristretto255 group
package ristretto

import (
	"github.com/gtank/ristretto255"

	"github.com/bytemare/crypto/internal"
)

const canonicalEncodingLength = 32

// Scalar implements the Scalar interface for Ristretto255 group scalars.
type Scalar struct {
	scalar *ristretto255.Scalar
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
	random := internal.RandomBytes(ristrettoInputLength)
	s.scalar.FromUniformBytes(random)

	return s
}

// Add returns the sum of the scalars, and does not change the receiver.
func (s *Scalar) Add(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := assert(scalar)

	return &Scalar{scalar: ristretto255.NewScalar().Add(s.scalar, sc.scalar)}
}

// Subtract returns the difference between the scalars, and does not change the receiver.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := assert(scalar)

	return &Scalar{scalar: ristretto255.NewScalar().Subtract(s.scalar, sc.scalar)}
}

// Multiply returns the multiplication of the scalars, and does not change the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := assert(scalar)

	return &Scalar{scalar: ristretto255.NewScalar().Multiply(s.scalar, sc.scalar)}
}

// Invert returns the scalar's modular inverse ( 1 / scalar ).
func (s *Scalar) Invert() internal.Scalar {
	return &Scalar{ristretto255.NewScalar().Invert(s.scalar)}
}

func (s *Scalar) Equal(scalar internal.Scalar) int {
	sc := assert(scalar)

	return s.scalar.Equal(sc.scalar)
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.scalar.Equal(ristretto255.NewScalar().Zero()) == 1
}

// Copy returns a copy of the Scalar.
func (s *Scalar) Copy() internal.Scalar {
	return &Scalar{ristretto255.NewScalar().Add(ristretto255.NewScalar(), s.scalar)}
}

// Decode decodes the input an sets the current scalar to its value, and returns it.
func (s *Scalar) Decode(in []byte) (internal.Scalar, error) {
	sc, err := decodeScalar(in)
	if err != nil {
		return nil, err
	}

	s.scalar = sc

	return s, nil
}

// Bytes returns the byte encoding of the scalar.
func (s *Scalar) Bytes() []byte {
	return s.scalar.Encode(nil)
}

func decodeScalar(scalar []byte) (*ristretto255.Scalar, error) {
	if len(scalar) == 0 {
		return nil, internal.ErrParamNilScalar
	}

	if len(scalar) != canonicalEncodingLength {
		return nil, internal.ErrParamScalarLength
	}

	s := ristretto255.NewScalar()
	if err := s.Decode(scalar); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *Scalar) Zero() internal.Scalar {
	s.scalar.Zero()
	return s
}
