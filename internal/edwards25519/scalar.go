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
	_, err := s.scalar.SetUniformBytes(internal.RandomBytes(inputLength))
	if err != nil {
		panic(err)
	}

	return s
}

// Add returns the sum of the scalars, and does not change the receiver.
func (s *Scalar) Add(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := assert(scalar)

	return &Scalar{scalar: edwards25519.NewScalar().Add(s.scalar, sc.scalar)}
}

// Subtract returns the difference between the scalars, and does not change the receiver.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := assert(scalar)

	return &Scalar{scalar: edwards25519.NewScalar().Subtract(s.scalar, sc.scalar)}
}

// Multiply returns the multiplication of the scalars, and does not change the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := assert(scalar)

	return &Scalar{scalar: edwards25519.NewScalar().Multiply(s.scalar, sc.scalar)}
}

// Invert returns the scalar's modular inverse ( 1 / scalar ), and does not change the receiver.
func (s *Scalar) Invert() internal.Scalar {
	return &Scalar{edwards25519.NewScalar().Invert(s.scalar)}
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

// Decode decodes the input an sets the current scalar to its value, and returns it.
func (s *Scalar) Decode(in []byte) (internal.Scalar, error) {
	sc, err := decodeScalar(in)
	if err != nil {
		return nil, err
	}

	s.scalar = sc

	return s, nil
}

// Bytes returns the byte encoding of the element.
func (s *Scalar) Bytes() []byte {
	return s.scalar.Bytes()
}

func (s *Scalar) Zero() internal.Scalar {
	s.scalar.Set(edwards25519.NewScalar())
	return s
}
