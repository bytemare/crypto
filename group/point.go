// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package group exposes a prime-order elliptic curve groups with additional hash-to-curve operations.
package group

import "github.com/bytemare/crypto/group/internal"

// Point represents a point on the curve of the prime-order group.
type Point struct {
	internal.Element
}

func newPoint(p internal.Element) *Point {
	return &Point{p}
}

// Add returns the sum of the Points, and does not change the receiver.
func (p *Point) Add(point *Point) *Point {
	if point == nil {
		panic(internal.ErrParamNilScalar)
	}
	return &Point{p.Element.Add(point.Element)}
}

// Sub returns the difference between the Points, and does not change the receiver.
func (p *Point) Sub(point *Point) *Point {
	if point == nil {
		panic(internal.ErrParamNilScalar)
	}
	return &Point{p.Element.Sub(point.Element)}
}

// Mult returns the scalar multiplication of the receiver point with the given scalar.
func (p *Point) Mult(scalar *Scalar) *Point {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}
	return &Point{p.Element.Mult(scalar.Scalar)}
}

// InvertMult returns the scalar multiplication of the receiver point with the inverse of the given scalar.
func (p *Point) InvertMult(scalar *Scalar) *Point {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}
	return &Point{p.Element.InvertMult(scalar.Scalar)}
}

// IsIdentity returns whether the point is the Group's identity point.
func (p *Point) IsIdentity() bool {
	return p.Element.IsIdentity()
}

// Copy returns a copy of the point.
func (p *Point) Copy() *Point {
	return &Point{p.Element.Copy()}
}

// Decode decodes the input and sets the current point to its value, and returns it.
func (p *Point) Decode(in []byte) (*Point, error) {
	q, err := p.Element.Decode(in)
	if err != nil {
		return nil, err
	}

	return &Point{q}, nil
}

// Bytes returns the compressed byte encoding of the point.
func (p *Point) Bytes() []byte {
	return p.Element.Bytes()
}
