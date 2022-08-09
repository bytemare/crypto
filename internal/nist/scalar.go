// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist

import (
	"encoding/base64"
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
	s     big.Int
	field *field
}

func newScalar(field *field) *Scalar {
	s := &Scalar{field: field}
	s.s.Set(zero)

	return s
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

func (s *Scalar) Zero() internal.Scalar {
	s.s.Set(zero)
	return s
}

func (s *Scalar) One() internal.Scalar {
	s.s.Set(one)
	return s
}

// Random sets the current scalar to a new random scalar and returns it.
func (s *Scalar) Random() internal.Scalar {
	for {
		s.field.Random(&s.s)

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
	s.field.Add(&s.s, &s.s, &sc.s)

	return s
}

// Subtract returns the difference between the scalars, and does not change the receiver.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := s.assert(scalar)
	s.field.sub(&s.s, &s.s, &sc.s)

	return s
}

// Multiply returns the multiplication of the scalars, and does not change the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := s.assert(scalar)
	s.field.Mul(&s.s, &s.s, &sc.s)

	return s
}

// Invert returns the scalar's modular inverse ( 1 / scalar ), and does not change the receiver.
func (s *Scalar) Invert() internal.Scalar {
	s.field.Inv(&s.s, &s.s)
	return s
}

func (s *Scalar) Equal(scalar internal.Scalar) int {
	if scalar == nil {
		return 0
	}

	sc := s.assert(scalar)

	switch s.s.Cmp(&sc.s) {
	case 0:
		return 1
	default:
		return 0
	}
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.field.AreEqual(&s.s, zero)
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
	cpy := &Scalar{field: s.field}
	cpy.s.Set(&s.s)

	return s
}

// Encode returns the compressed byte encoding of the element.
func (s *Scalar) Encode() []byte {
	byteLen := (s.field.BitLen() + 7) / 8
	scalar := make([]byte, byteLen)

	return s.s.FillBytes(scalar)
}

// Decode decodes the input an sets the current scalar to its value, and returns it.
func (s *Scalar) Decode(in []byte) error {
	if len(in) == 0 {
		return internal.ErrParamNilScalar
	}

	// warning - SetBytes interprets the input as a non-signed integer, so this will always be false
	e := new(big.Int).SetBytes(in)
	if e.Sign() < 0 {
		return errParamNegScalar
	}

	if s.field.Order().Cmp(e) <= 0 {
		return errParamScalarTooBig
	}

	s.s.Set(e)

	return nil
}

// MarshalBinary returns the compressed byte encoding of the element.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded element.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	return s.Decode(data)
}

// MarshalText implements the encoding.MarshalText interface.
func (s *Scalar) MarshalText() (text []byte, err error) {
	b := s.Encode()
	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

// UnmarshalText implements the encoding.UnmarshalText interface.
func (s *Scalar) UnmarshalText(text []byte) error {
	sb, err := base64.StdEncoding.DecodeString(string(text))
	if err == nil {
		return s.Decode(sb)
	}

	return err
}
