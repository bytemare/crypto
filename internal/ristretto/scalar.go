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
	"encoding/base64"
	"fmt"

	"github.com/gtank/ristretto255"

	"github.com/bytemare/crypto/internal"
)

const canonicalEncodingLength = 32

var scOne Scalar

func init() {
	scOne = Scalar{*ristretto255.NewScalar()}
	if err := scOne.Decode([]byte{
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}); err != nil {
		panic(err)
	}
}

// Scalar implements the Scalar interface for Ristretto255 group scalars.
type Scalar struct {
	scalar ristretto255.Scalar
}

func assert(scalar internal.Scalar) *Scalar {
	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastScalar)
	}

	return sc
}

// Zero sets the scalar to 0, and returns it.
func (s *Scalar) Zero() internal.Scalar {
	s.scalar.Zero()
	return s
}

// One sets the scalar to 1, and returns it.
func (s *Scalar) One() internal.Scalar {
	s.set(&scOne)
	return s
}

// Random sets the current scalar to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() internal.Scalar {
	for {
		random := internal.RandomBytes(inputLength)
		s.scalar.FromUniformBytes(random)

		if !s.IsZero() {
			return s
		}
	}
}

// Add sets the receiver to the sum of the input and the receiver, and returns the receiver.
func (s *Scalar) Add(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := assert(scalar)
	s.scalar.Add(&s.scalar, &sc.scalar)

	return s
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := assert(scalar)
	s.scalar.Subtract(&s.scalar, &sc.scalar)

	return s
}

// Multiply multiplies the receiver with the input, and returns the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := assert(scalar)
	s.scalar.Multiply(&s.scalar, &sc.scalar)

	return s
}

// Invert sets the receiver to the scalar's modular inverse ( 1 / scalar ), and returns it.
func (s *Scalar) Invert() internal.Scalar {
	s.scalar.Invert(&s.scalar)
	return s
}

// Equal returns 1 if the scalars are equal, and 0 otherwise.
func (s *Scalar) Equal(scalar internal.Scalar) int {
	if scalar == nil {
		return 0
	}

	sc := assert(scalar)

	return s.scalar.Equal(&sc.scalar)
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.scalar.Equal(ristretto255.NewScalar().Zero()) == 1
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

	ec := assert(scalar)
	s.scalar = ec.scalar

	return s
}

// Copy returns a copy of the receiver.
func (s *Scalar) Copy() internal.Scalar {
	return &Scalar{*ristretto255.NewScalar().Add(ristretto255.NewScalar(), &s.scalar)}
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	return s.scalar.Encode(nil)
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (s *Scalar) Decode(data []byte) error {
	sc, err := decodeScalar(data)
	if err != nil {
		return err
	}

	s.scalar = *sc

	return nil
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
		return nil, fmt.Errorf("ristretto scalar Decode: %w", err)
	}

	return s, nil
}

// MarshalBinary returns the compressed byte encoding of the scalar.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded scalar.
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

	return fmt.Errorf("ristretto scalar UnmarshalText: %w", err)
}
