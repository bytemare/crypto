// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package curve25519 implements a prime-order group over Curve25519 with hash-to-curve.
package curve25519

import (
	"fmt"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"

	"github.com/bytemare/crypto/group/internal"
)

// Element represents a Curve25519 point. It wraps an Edwards25519 implementation to leverage its optimized operations.
type Element struct {
	element *edwards25519.Point
}

func newPoint() *Element {
	return &Element{edwards25519.NewIdentityPoint()}
}

// Add returns the sum of the Elements, and does not change the receiver.
func (e *Element) Add(element internal.Point) internal.Point {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ele, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Element{edwards25519.NewIdentityPoint().Add(e.element, ele.element)}
}

// Sub returns the difference between the Elements, and does not change the receiver.
func (e *Element) Sub(element internal.Point) internal.Point {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ele, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Element{edwards25519.NewIdentityPoint().Subtract(e.element, ele.element)}
}

// Mult returns the scalar multiplication of the receiver element with the given scalar.
func (e *Element) Mult(scalar internal.Scalar) internal.Point {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	sc, ok := scalar.(*Scalar)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return &Element{edwards25519.NewIdentityPoint().ScalarMult(sc.scalar, e.element)}
}

// InvertMult returns the scalar multiplication of the receiver element with the inverse of the given scalar.
func (e *Element) InvertMult(scalar internal.Scalar) internal.Point {
	if scalar == nil {
		panic(internal.ErrParamNilScalar)
	}

	return e.Mult(scalar.Invert())
}

// IsIdentity returns whether the element is the Group's identity element.
func (e *Element) IsIdentity() bool {
	id := edwards25519.NewIdentityPoint()
	return e.element.Equal(id) == 1
}

// Copy returns a copy of the element.
func (e *Element) Copy() internal.Point {
	n := edwards25519.NewIdentityPoint()
	if _, err := n.SetBytes(e.element.Bytes()); err != nil {
		panic(err)
	}

	return &Element{element: n}
}

// Decode decodes the input an sets the current element to its value, and returns it.
func (e *Element) Decode(in []byte) (internal.Point, error) {
	u, err := new(field.Element).SetBytes(in)
	if err != nil {
		return nil, err
	}

	y := MontgomeryUToEdwardsY(u)

	if _, err := e.element.SetBytes(y.Bytes()); err != nil {
		return nil, fmt.Errorf("decoding element : %w", err)
	}

	return e, nil
}

// Bytes returns the compressed byte encoding of the element.
func (e *Element) Bytes() []byte {
	return e.element.BytesMontgomery()
}
