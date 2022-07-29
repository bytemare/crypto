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

func (s *Scalar) check(scalar internal.Scalar) *Scalar {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

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
	s.s = s.field.Random()
	return s
}

// Add returns the sum of the scalars, and does not change the receiver.
func (s *Scalar) Add(scalar internal.Scalar) internal.Scalar {
	sc := s.check(scalar)

	return &Scalar{
		s:     s.field.Add(s.s, sc.s),
		field: s.field,
	}
}

// Sub returns the difference between the scalars, and does not change the receiver.
func (s *Scalar) Sub(scalar internal.Scalar) internal.Scalar {
	sc := s.check(scalar)

	return &Scalar{
		s:     s.field.sub(s.s, sc.s),
		field: s.field,
	}
}

// Mult returns the multiplication of the scalars, and does not change the receiver.
func (s *Scalar) Mult(scalar internal.Scalar) internal.Scalar {
	sc := s.check(scalar)

	return &Scalar{
		s:     s.field.Mul(s.s, sc.s),
		field: s.field,
	}
}

// Invert returns the scalar's modular inverse ( 1 / scalar ), and does not change the receiver.
func (s *Scalar) Invert() internal.Scalar {
	return &Scalar{
		s:     s.field.Inv(s.s),
		field: s.field,
	}
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.field.AreEqual(s.s, s.field.Zero())
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
func (s *Scalar) Bytes() []byte {
	byteLen := (s.field.BitLen() + 7) / 8
	scalar := make([]byte, byteLen)

	return s.s.FillBytes(scalar)
}
