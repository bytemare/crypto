// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package crypto exposes a prime-order elliptic curve groups with additional hash-to-curve operations.
package crypto

import "github.com/bytemare/crypto/internal"

// Element represents a point on the curve of the prime-order group.
type Element struct {
	internal.Element
}

func newPoint(p internal.Element) *Element {
	return &Element{p}
}

// Add returns the sum of the Points, and does not change the receiver.
func (p *Element) Add(point *Element) *Element {
	if point == nil {
		panic(internal.ErrParamNilScalar)
	}

	return &Element{p.Element.Add(point.Element)}
}

// Sub returns the difference between the Points, and does not change the receiver.
func (p *Element) Sub(point *Element) *Element {
	if point == nil {
		panic(internal.ErrParamNilScalar)
	}

	return &Element{p.Element.Sub(point.Element)}
}

// Mult returns the scalar multiplication of the receiver point with the given scalar.
func (p *Element) Mult(scalar *Scalar) *Element {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	return &Element{p.Element.Mult(scalar.Scalar)}
}

// IsIdentity returns whether the point is the Group's identity point.
func (p *Element) IsIdentity() bool {
	return p.Element.IsIdentity()
}

// Copy returns a copy of the point.
func (p *Element) Copy() *Element {
	return &Element{p.Element.Copy()}
}

// Decode decodes the input and sets the current point to its value, and returns it.
func (p *Element) Decode(in []byte) (*Element, error) {
	q, err := p.Element.Decode(in)
	if err != nil {
		return nil, err
	}

	return &Element{q}, nil
}

// Bytes returns the compressed byte encoding of the point.
func (p *Element) Bytes() []byte {
	return p.Element.Bytes()
}
