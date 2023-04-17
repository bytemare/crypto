// SPDX-License-Identifier: MIT
//
// Copyright (C)2020-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package secp256k1

import (
	"crypto/subtle"
	"math/big"

	"github.com/bytemare/crypto/internal"
)

// Scalar implements the Scalar interface for Edwards25519 group scalars.
type Scalar struct {
	scalar big.Int
}

var (
	scZero = big.NewInt(0)
	scOne  = big.NewInt(1)
)

func newScalar() *Scalar {
	return &Scalar{scalar: big.Int{}}
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
	s.scalar.Set(scZero)
	return s
}

// One sets the scalar to 1, and returns it.
func (s *Scalar) One() internal.Scalar {
	s.scalar.Set(scOne)
	return s
}

// Random sets the current scalar to a new random scalar and returns it.
// The random source is crypto/rand, and this functions is guaranteed to return a non-zero scalar.
func (s *Scalar) Random() internal.Scalar {
	for {
		fn.Random(&s.scalar)

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
	fn.Add(&s.scalar, &s.scalar, &sc.scalar)

	return s
}

// Subtract subtracts the input from the receiver, and returns the receiver.
func (s *Scalar) Subtract(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s
	}

	sc := assert(scalar)
	fn.Sub(&s.scalar, &s.scalar, &sc.scalar)

	return s
}

// Multiply multiplies the receiver with the input, and returns the receiver.
func (s *Scalar) Multiply(scalar internal.Scalar) internal.Scalar {
	if scalar == nil {
		return s.Zero()
	}

	sc := assert(scalar)
	fn.Mul(&s.scalar, &s.scalar, &sc.scalar)

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

	sc := assert(scalar)
	fn.Exponent(&s.scalar, &s.scalar, &sc.scalar)

	return s
}

// Invert sets the receiver to its modular inverse ( 1 / s ), and returns it.
func (s *Scalar) Invert() internal.Scalar {
	fn.Inv(&s.scalar, &s.scalar)
	return s
}

// Equal returns 1 if the scalars are equal, and 0 otherwise.
func (s *Scalar) Equal(scalar internal.Scalar) int {
	if scalar == nil {
		return 0
	}

	sc := assert(scalar)

	return subtle.ConstantTimeCompare(s.scalar.Bytes(), sc.scalar.Bytes())
}

// LessOrEqual returns 1 if s <= scalar and 0 otherwise.
func (s *Scalar) LessOrEqual(scalar internal.Scalar) int {
	sc := assert(scalar)

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
	return fn.AreEqual(&s.scalar, scZero)
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
	s.scalar.Set(&ec.scalar)

	return s
}

// SetInt sets s to i modulo the field order, and returns an error if one occurs.
func (s *Scalar) SetInt(i *big.Int) error {
	s.scalar.Set(i)
	fn.Mod(&s.scalar)

	return nil
}

// Copy returns a copy of the receiver.
func (s *Scalar) Copy() internal.Scalar {
	cpy := newScalar()
	cpy.scalar.Set(&s.scalar)

	return cpy
}

// Encode returns the compressed byte encoding of the scalar.
func (s *Scalar) Encode() []byte {
	byteLen := (fn.BitLen() + 7) / 8
	scalar := make([]byte, byteLen)

	return s.scalar.FillBytes(scalar)
}

func (s *Scalar) decode(in []byte) error {
	if len(in) == 0 {
		return internal.ErrParamNilScalar
	}

	// warning - SetBytes interprets the input as a non-signed integer, so this will always be false
	tmp := new(big.Int).SetBytes(in)
	if tmp.Sign() < 0 {
		return internal.ErrParamNegScalar
	}

	if fn.Order().Cmp(tmp) <= 0 {
		return internal.ErrParamScalarTooBig
	}

	s.scalar.Set(tmp)

	return nil
}

// Decode sets the receiver to a decoding of the input data, and returns an error on failure.
func (s *Scalar) Decode(in []byte) error {
	return s.decode(in)
}

// MarshalBinary returns the compressed byte encoding of the scalar.
func (s *Scalar) MarshalBinary() (data []byte, err error) {
	return s.Encode(), nil
}

// UnmarshalBinary sets e to the decoding of the byte encoded scalar.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	return s.Decode(data)
}
