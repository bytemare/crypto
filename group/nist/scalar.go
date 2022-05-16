// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist

import (
	"github.com/bytemare/crypto/group/internal"
	nist "github.com/bytemare/crypto/group/nist/internal"
)

// Scalar implements the Scalar interface for group scalars.
type Scalar[Point nist.NistECPoint[Point]] struct {
	group  *nist.Group[Point]
	scalar *nist.Scalar
}

func (s *Scalar[any]) newScalar(scalar *nist.Scalar) *Scalar[any] {
	return &Scalar[any]{s.group, scalar}
}

// Random sets the current scalar to a new random scalar and returns it.
func (s *Scalar[any]) Random() internal.Scalar {
	s.scalar.Random()
	return s
}

// Add returns the sum of the scalars, and does not change the receiver.
func (s *Scalar[any]) Add(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	sc, ok := scalar.(*Scalar[any])
	if !ok {
		panic(internal.ErrCastScalar)
	}

	return s.newScalar(s.group.NewScalar().Add(s.scalar, sc.scalar))
}

// Sub returns the difference between the scalars, and does not change the receiver.
func (s *Scalar[any]) Sub(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	sc, ok := scalar.(*Scalar[any])
	if !ok {
		panic("could not cast to same group scalar : wrong group ?")
	}

	return s.newScalar(s.group.NewScalar().Sub(s.scalar, sc.scalar))
}

// Mult returns the multiplication of the scalars, and does not change the receiver.
func (s *Scalar[any]) Mult(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	sc, ok := scalar.(*Scalar[any])
	if !ok {
		panic("could not cast to same group scalar : wrong group ?")
	}

	return s.newScalar(s.group.NewScalar().Mult(s.scalar, sc.scalar))
}

// Invert returns the scalar's modular inverse ( 1 / scalar ), and does not change the receiver.
func (s *Scalar[any]) Invert() internal.Scalar {
	return s.newScalar(s.group.NewScalar().Invert(s.scalar))
}

// IsZero returns whether the scalar is 0.
func (s *Scalar[any]) IsZero() bool {
	return s.scalar.IsZero()
}

// Copy returns a copy of the Scalar.
func (s *Scalar[any]) Copy() internal.Scalar {
	return s.newScalar(s.scalar.Copy())
}

// Decode decodes the input an sets the current scalar to its value, and returns it.
func (s *Scalar[any]) Decode(in []byte) (internal.Scalar, error) {
	sc, err := s.scalar.Decode(in)
	if err != nil {
		return nil, err
	}

	s.scalar = sc

	return s, nil
}

// Bytes returns the byte encoding of the element.
func (s *Scalar[any]) Bytes() []byte {
	return s.scalar.Bytes()
}
