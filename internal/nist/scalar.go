// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package nist

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"

	"github.com/bytemare/crypto/internal"
)

var (
	errParamNegScalar    = errors.New("negative scalar")
	errParamScalarTooBig = errors.New("scalar too big")
)

// Scalar implements the Scalar interface for group scalars.
type Scalar struct {
	field *field
	s     big.Int
}

func newScalar(field *field) *Scalar {
	s := &Scalar{
		field: field,
		s:     big.Int{},
	}
	s.s.Set(zero)

	return s
}

func (s *Scalar) assert(scalar internal.Scalar) *Scalar {
	_sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastScalar)
	}

	if !s.field.isEqual(_sc.field) {
		panic(internal.ErrWrongField)
	}

	return _sc
}

// Zero sets s to 0, and returns it.
func (s *Scalar) Zero() internal.Scalar {
	s.s.Set(zero)
	return s
}

// One sets s to 1, and returns it.
func (s *Scalar) One() internal.Scalar {
	s.s.Set(one)
	return s
}

// Random sets s to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() internal.Scalar {
	for {
		s.field.random(&s.s)

		if !s.IsZero() {
			return s
		}
	}
}

// Add returns s+scalar, and returns s.
func (s *Scalar) Add(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := s.assert(scalar)
	s.field.add(&s.s, &s.s, &sc.s)

	return s
}

// Subtract returns s-scalar, and returns s.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := s.assert(scalar)
	s.field.sub(&s.s, &s.s, &sc.s)

	return s
}

// Multiply sets s to s*scalar, and returns s.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := s.assert(scalar)
	s.field.mul(&s.s, &s.s, &sc.s)

	return s
}

// Pow sets s to s**scalar modulo the group order, and returns s. If scalar is nil, it returns 1.
func (s *Scalar) Pow(scalar internal.Scalar) internal.Scalar {
	if scalar == nil || scalar.IsZero() {
		return s.One()
	}

	if scalar.Equal(scalar.Copy().One()) == 1 {
		return s
	}

	sc := s.assert(scalar)
	s.field.exponent(&s.s, &s.s, &sc.s)

	return s
}

// Invert sets s to its modular inverse ( 1 / s ).
func (s *Scalar) Invert() internal.Scalar {
	s.field.inv(&s.s, &s.s)
	return s
}

// Equal returns 1 if the s == scalar are equal, and 0 otherwise.
func (s *Scalar) Equal(scalar internal.Scalar) int {
	if scalar == nil {
		return 0
	}

	sc := s.assert(scalar)

	return subtle.ConstantTimeCompare(s.s.Bytes(), sc.s.Bytes())
}

// LessOrEqual returns 1 if s <= scalar, and 0 otherwise.
func (s *Scalar) LessOrEqual(scalar internal.Scalar) int {
	sc := s.assert(scalar)

	ienc := s.Encode()
	jenc := sc.Encode()

	leni := len(ienc)
	if leni != len(jenc) {
		panic(internal.ErrParamScalarLength)
	}

	var res bool

	for i := 0; i < leni; i++ {
		res = res || (ienc[i] > jenc[i])
	}

	if res {
		return 0
	}

	return 1
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.field.areEqual(&s.s, zero)
}

func (s *Scalar) set(scalar *Scalar) *Scalar {
	*s = *scalar
	return s
}

// Set sets the receiver to the value of the argument scalar, and returns the receiver.
func (s *Scalar) Set(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.set(nil)
	}

	ec := s.assert(scalar)
	s.s.Set(&ec.s)

	return s
}

// Copy returns a copy of the Scalar.
func (s *Scalar) Copy() internal.Scalar {
	cpy := newScalar(s.field)
	cpy.s.Set(&s.s)

	return cpy
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	byteLen := (s.field.bitLen() + 7) / 8
	scalar := make([]byte, byteLen)

	return s.s.FillBytes(scalar)
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (s *Scalar) Decode(data []byte) error {
	if len(data) == 0 {
		return internal.ErrParamNilScalar
	}

	// warning - SetBytes interprets the input as a non-signed integer, so this will always be false
	tmp := new(big.Int).SetBytes(data)
	if tmp.Sign() < 0 {
		return errParamNegScalar
	}

	if s.field.order().Cmp(tmp) <= 0 {
		return errParamScalarTooBig
	}

	s.s.Set(tmp)

	return nil
}

// MarshalBinary returns the compressed byte encoding of the scalar.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded scalar.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	if err := s.Decode(data); err != nil {
		return fmt.Errorf("nist: %w", err)
	}

	return nil
}
