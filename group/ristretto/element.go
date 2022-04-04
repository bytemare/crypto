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
	"fmt"

	"github.com/gtank/ristretto255"

	"github.com/bytemare/crypto/group/internal"
)

// Point implements the Point interface for the Ristretto255 group element.
type Point struct {
	point *ristretto255.Element
}

// Add adds the argument to the receiver, sets the receiver to the result and returns it.
func (p *Point) Add(element internal.Point) internal.Point {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ele, ok := element.(*Point)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Point{ristretto255.NewElement().Add(p.point, ele.point)}
}

// Sub subtracts the argument from the receiver, sets the receiver to the result and returns it.
func (p *Point) Sub(element internal.Point) internal.Point {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ele, ok := element.(*Point)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Point{ristretto255.NewElement().Subtract(p.point, ele.point)}
}

// Mult returns the scalar multiplication of the receiver element with the given scalar.
func (p *Point) Mult(scalar internal.Scalar) internal.Point {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Point{ristretto255.NewElement().ScalarMult(sc.scalar, p.point)}
}

// InvertMult returns the scalar multiplication of the receiver element with the inverse of the given scalar.
func (p *Point) InvertMult(scalar internal.Scalar) internal.Point {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	return p.Mult(scalar.Invert())
}

// IsIdentity returns whether the element is the group's identity element.
func (p *Point) IsIdentity() bool {
	id := ristretto255.NewElement().Zero()
	return p.point.Equal(id) == 1
}

// Copy returns a copy of the element.
func (p *Point) Copy() internal.Point {
	n := ristretto255.NewElement()
	if err := n.Decode(p.point.Encode(nil)); err != nil {
		panic(err)
	}

	return &Point{point: n}
}

// Decode decodes the input an sets the current element to its value, and returns it.
func (p *Point) Decode(in []byte) (internal.Point, error) {
	el, err := decodeElement(in)
	if err != nil {
		return nil, err
	}

	// superfluous identity check
	if el.Equal(ristretto255.NewElement().Zero()) == 1 {
		return nil, internal.ErrIdentity
	}

	p.point = el

	return p, nil
}

// Bytes returns the compressed byte encoding of the element.
func (p *Point) Bytes() []byte {
	return p.point.Encode(nil)
}

// Base returns the group's base point.
func (p *Point) Base() internal.Point {
	p.point = ristretto255.NewElement().Base()
	return p
}

func decodeElement(element []byte) (*ristretto255.Element, error) {
	if len(element) == 0 {
		return nil, internal.ErrParamNilPoint
	}

	e := ristretto255.NewElement()
	if err := e.Decode(element); err != nil {
		return nil, fmt.Errorf("decoding element : %w", err)
	}

	return e, nil
}
