// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package other wraps an hash-to-curve implementation and exposes functions for operations on points and scalars.
package other

import (
	nist "crypto/elliptic"
	"log"
	"math/big"

	Curve "github.com/armfazh/h2c-go-ref/curve"
	C "github.com/armfazh/tozan-ecc/curve"
	"github.com/armfazh/tozan-ecc/field"

	"github.com/bytemare/crypto/group/internal"
)

// Point implements the Point interface for Hash-to-Curve points.
type Point struct {
	*Hash2Curve
	*curve
	point C.Point
}

// Add adds the argument to the receiver, sets the receiver to the result and returns it.
func (p *Point) Add(element internal.Element) internal.Element {
	if element == nil {
		panic("element is nil")
	}

	po, ok := element.(*Point)
	if !ok {
		panic("could not cast to same group element : wrong group ?")
	}

	return &Point{
		Hash2Curve: p.Hash2Curve,
		curve:      p.curve,
		point:      p.curve.Add(p.point, po.point),
	}
}

// Sub subtracts the argument from the receiver, sets the receiver to the result and returns it.
func (p *Point) Sub(element internal.Element) internal.Element {
	if element == nil {
		panic("element is nil")
	}

	pt, ok := element.(*Point)
	if !ok {
		panic("could not cast to same group element : wrong group ?")
	}

	return &Point{
		Hash2Curve: p.Hash2Curve,
		curve:      p.curve,
		point:      p.curve.Add(p.point, p.Neg(pt.point)),
	}
}

// Mult returns the scalar multiplication of the receiver element with the given scalar.
func (p *Point) Mult(scalar internal.Scalar) internal.Element {
	sc, ok := scalar.(*Scalar)
	if !ok {
		panic("could not cast to hash2curve scalar")
	}

	h2 := getH2C(p.suite, nil)

	if !h2.GetHashToScalar().GetScalarField().IsEqual(sc.f) {
		panic("cannot multiply with scalar from a different field")
	}

	return &Point{
		Hash2Curve: p.Hash2Curve,
		curve:      p.curve,
		point:      p.ScalarMult(p.point, sc.s.Polynomial()[0]),
	}
}

// InvertMult returns the scalar multiplication of the receiver element with the inverse of the given scalar.
func (p *Point) InvertMult(s internal.Scalar) internal.Element {
	if s == nil {
		panic(internal.ErrParamNilScalar)
	}

	return p.Mult(s.Invert())
}

// IsIdentity returns whether the element is the Group's identity element.
func (p *Point) IsIdentity() bool {
	return p.point.IsIdentity()
}

// Copy returns a copy of the element.
func (p *Point) Copy() internal.Element {
	return &Point{
		Hash2Curve: p.Hash2Curve,
		curve:      p.curve,
		point:      p.point.Copy(),
	}
}

// Bytes returns the compressed byte encoding of the element.
func (p *Point) Bytes() []byte {
	var x, y *big.Int
	if p.point.X() == nil {
		x = big.NewInt(0)
		y = big.NewInt(1)
	} else {
		x = p.point.X().Polynomial()[0]
		y = p.point.Y().Polynomial()[0]
	}

	log.Println(x.Bytes())
	log.Println(y.Bytes())

	return encodeSignPrefix448(x, y, pointLen(p.Field().BitLen()))
}

// Decode decodes the input and sets the current element to its value, and returns it.
func (p *Point) Decode(input []byte) (internal.Element, error) {
	if p.id == Curve.P256 || p.id == Curve.P384 || p.id == Curve.P521 {
		x, y := nist.UnmarshalCompressed(h2cToNist(p.id), input)
		if x == nil {
			return nil, errParamDecPoint
		}

		if err := p.set(x, y); err != nil {
			return nil, err
		}

		return p, nil
	}

	if p.id == Curve.Curve448 || p.id == Curve.Edwards448 {
		return p.recover448(input)
	}

	return p.recoverPoint(input)
}

func (p *Point) set(x, y *big.Int) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	X := p.Field().Elt(x)
	Y := p.Field().Elt(y)

	p.point = p.NewPoint(X, Y)

	return err
}

func getY(f field.Field, input []byte) (*big.Int, error) {
	byteLen := (f.BitLen() + 7) / 8
	if len(input) != 1+byteLen {
		return nil, errParamInvalidSize
	}

	y := new(big.Int).SetBytes(input[1:])
	if y.Cmp(f.Order()) >= 0 {
		return nil, errParamDecYExceeds
	}

	return y, nil
}

func getX(f field.Field, input []byte) (*big.Int, error) {
	byteLen := (f.BitLen() + 7) / 8
	if len(input) != 1+byteLen {
		return nil, errParamInvalidSize
	}

	if input[0] != 2 && input[0] != 3 {
		return nil, errParamInvalidFormat
	}

	x := new(big.Int).SetBytes(input[1:])
	if x.Cmp(f.Order()) >= 0 {
		return nil, errParamDecXExceeds
	}

	return x, nil
}
