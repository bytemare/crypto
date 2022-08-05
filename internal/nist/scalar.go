// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist

import (
	"errors"
	"math/big"

	"github.com/bytemare/crypto/internal"
)

var (
	errParamNegScalar    = errors.New("negative scalar")
	errParamScalarTooBig = errors.New("scalar too big")
)

// Scalar implements the Scalar interface for group scalars.
type Scalar struct {
	s     *big.Int
	field *field
}

func newScalar(field *field) *Scalar {
	return &Scalar{
		s:     field.Zero(),
		field: field,
	}
}

func (s *Scalar) assert(scalar internal.Scalar) *Scalar {
	sc, ok := scalar.(*Scalar)
	if !ok {
		panic("could not cast to same group scalar : wrong group ?")
	}

	if !s.field.IsEqual(sc.field) {
		panic("incompatible fields")
	}

	return sc
}

// Random sets the current scalar to a new random scalar and returns it.
func (s *Scalar) Random() internal.Scalar {
	for {
		s.s = s.field.Random()

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

	sc := s.assert(scalar)
	s.s.Add(s.s, sc.s)

	return s
}

// Subtract returns the difference between the scalars, and does not change the receiver.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := s.assert(scalar)
	s.s.Sub(s.s, sc.s)

	return s
}

// Multiply returns the multiplication of the scalars, and does not change the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := s.assert(scalar)
	s.s.Mul(s.s, sc.s)

	return s
}

// Invert returns the scalar's modular inverse ( 1 / scalar ), and does not change the receiver.
func (s *Scalar) Invert() internal.Scalar {
	s.s = s.field.Inv(s.s)
	return s
}

func (s *Scalar) Equal(scalar internal.Scalar) int {
	if scalar == nil {
		return 0
	}

	sc := s.assert(scalar)
	switch sc.s.Cmp(sc.s) {
	case 0:
		return 1
	default:
		return 0
	}
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.field.AreEqual(s.s, s.field.Zero())
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

	ec := s.assert(scalar)

	return s.set(ec)
}

// Copy returns a copy of the Scalar.
func (s *Scalar) Copy() internal.Scalar {
	return &Scalar{
		s:     new(big.Int).Set(s.s),
		field: s.field,
	}
}

// Decode decodes the input an sets the current scalar to its value, and returns it.
func (s *Scalar) Decode(in []byte) (internal.Scalar, error) {
	if len(in) == 0 {
		return nil, internal.ErrParamNilScalar
	}

	// warning - SetBytes interprets the input as a non-signed integer, so this will always be negative
	e := new(big.Int).SetBytes(in)
	if e.Sign() < 0 {
		return nil, errParamNegScalar
	}

	if s.field.Order().Cmp(e) <= 0 {
		return nil, errParamScalarTooBig
	}

	s.s = s.field.Element(e)

	return s, nil
}

// Bytes returns the byte encoding of the element.
func (s *Scalar) Encode() []byte {
	byteLen := (s.field.BitLen() + 7) / 8
	scalar := make([]byte, byteLen)

	return s.s.FillBytes(scalar)
}

func (s *Scalar) Zero() internal.Scalar {
	s.s = s.field.Zero()
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
