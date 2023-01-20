// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package edwards25519

import (
	"fmt"
	"math/big"

	ed "filippo.io/edwards25519"

	"github.com/bytemare/crypto/internal"
)

const (
	inputLength = 64
)

var (
	scZero Scalar
	scOne  Scalar
	order  big.Int
)

func init() {
	scZero = Scalar{*ed.NewScalar()}
	if err := scZero.Decode([]byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}); err != nil {
		panic(err)
	}

	scOne = Scalar{*ed.NewScalar()}
	if err := scOne.Decode([]byte{
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}); err != nil {
		panic(err)
	}

	if _, ok := order.SetString(orderPrime, 10); !ok {
		panic(internal.ErrBigIntConversion)
	}
}

// Scalar implements the Scalar interface for Ristretto255 group scalars.
type Scalar struct {
	scalar ed.Scalar
}

func assert(scalar internal.Scalar) *Scalar {
	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastScalar)
	}

	return &Scalar{*ed.NewScalar().Set(&sc.scalar)}
}

func (s *Scalar) set(scalar *ed.Scalar) *Scalar {
	s.scalar = *scalar
	return s
}

// Zero sets the scalar to 0, and returns it.
func (s *Scalar) Zero() internal.Scalar {
	s.scalar = *ed.NewScalar()
	return s
}

// One sets the scalar to 1, and returns it.
func (s *Scalar) One() internal.Scalar {
	s.set(&scOne.scalar)
	return s
}

// Random sets the current scalar to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() internal.Scalar {
	for {
		random := internal.RandomBytes(inputLength)
		if _, err := s.scalar.SetUniformBytes(random); err != nil {
			panic(err)
		}

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

func (s *Scalar) multiply(scalar *Scalar) {
	s.scalar.Multiply(&s.scalar, &scalar.scalar)
}

// Multiply multiplies the receiver with the input, and returns the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := assert(scalar)
	s.multiply(sc)

	return s
}

func getMSBit(in byte) int {
	for i := 7; i >= 0; i-- {
		mask := byte(1 << uint(i))
		if in&mask != 0 {
			return i
		}
	}

	return 0
}

func getMSByte(in []byte) int {
	msb := 0

	for i, b := range in {
		if b != 0 {
			msb = i
		}
	}

	return msb
}

func (s *Scalar) square() {
	s.scalar.Multiply(&s.scalar, &s.scalar)
}

// Pow sets s to s**scalar modulo the group order, and returns s. If scalar is nil, it returns 1.
func (s *Scalar) Pow(scalar internal.Scalar) internal.Scalar {
	sc := assert(scalar)
	exponent := sc.scalar.Bytes()
	msbyte := getMSByte(exponent)
	msbit := getMSBit(exponent[msbyte])

	result := s.copy()
	dummy := s.copy()

	for i := 31; i >= 0; i-- {
		exp := exponent[i]
		firstByte := i == msbyte

		for j := 7; j >= 0; j-- {
			run := i < msbyte || (firstByte && j < msbit)
			currentBitValue := exp & byte(1<<byte(j))

			if run {
				result.square()

				if currentBitValue != 0 {
					result.multiply(s)
				} else {
					dummy.multiply(s)
				}
			} else {
				dummy.square()
				dummy.multiply(s)
			}
		}
	}

	switch {
	case sc.IsZero():
		s.set(&scOne.scalar)
	case sc.scalar.Equal(&scOne.scalar) == 1:
		s.set(&s.scalar)
	default:
		s.set(&result.scalar)
	}

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

// LessOrEqual returns 1 if s <= scalar and 0 otherwise.
func (s *Scalar) LessOrEqual(scalar internal.Scalar) int {
	sc := assert(scalar)

	ienc := s.Encode()
	jenc := sc.Encode()

	i := len(ienc)
	if i != len(jenc) {
		panic(internal.ErrParamScalarLength)
	}

	var res bool

	for i--; i >= 0; i-- {
		res = res || (ienc[i] > jenc[i])
	}

	if res {
		return 0
	}

	return 1
}

// IsZero returns whether the scalar is 0.
func (s *Scalar) IsZero() bool {
	return s.scalar.Equal(ed.NewScalar()) == 1
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

// SetInt sets s to i modulo the field order, and returns an error if one occurs.
func (s *Scalar) SetInt(i *big.Int) error {
	a := new(big.Int).Set(i)

	bytes := make([]byte, 32)
	bytes = a.Mod(a, &order).FillBytes(bytes)

	for j, k := 0, len(bytes)-1; j < k; j, k = j+1, k-1 {
		bytes[j], bytes[k] = bytes[k], bytes[j]
	}

	return s.Decode(bytes)
}

func (s *Scalar) copy() *Scalar {
	return &Scalar{*ed.NewScalar().Set(&s.scalar)}
}

// Copy returns a copy of the receiver.
func (s *Scalar) Copy() internal.Scalar {
	return &Scalar{*ed.NewScalar().Set(&s.scalar)}
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	return s.scalar.Bytes()
}

func decodeScalar(scalar []byte) (*ed.Scalar, error) {
	if len(scalar) == 0 {
		return nil, internal.ErrParamNilScalar
	}

	if len(scalar) != canonicalEncodingLength {
		return nil, internal.ErrParamScalarLength
	}

	s := ed.NewScalar()
	if _, err := s.SetCanonicalBytes(scalar); err != nil {
		return nil, fmt.Errorf("ristretto scalar Decode: %w", err)
	}

	return s, nil
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (s *Scalar) Decode(in []byte) error {
	sc, err := decodeScalar(in)
	if err != nil {
		return err
	}

	s.scalar = *sc

	return nil
}

// MarshalBinary returns the compressed byte encoding of the scalar.
func (s *Scalar) MarshalBinary() (data []byte, err error) {
	return s.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded scalar.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	if err := s.Decode(data); err != nil {
		return fmt.Errorf("edwards25519: %w", err)
	}

	return nil
}
