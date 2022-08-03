// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package edwards25519 wraps filippo.io/edwards25519 and exposes a simple prime-order group API with hash-to-curve.
package edwards25519

import (
	"fmt"

	"filippo.io/edwards25519"

	"github.com/bytemare/crypto/internal"
)

// Element represents an Edwards25519 point.
// It wraps an Edwards25519 implementation to leverage its optimized operations.
type Element struct {
	element *edwards25519.Point
}

func checkElement(element internal.Element) *Element {
	if element == nil {
		panic(internal.ErrParamNilPoint)
	}

	ec, ok := element.(*Element)
	if !ok {
		panic(internal.ErrCastElement)
	}

	return ec
}

func (e *Element) Base() internal.Element {
	e.element.Set(edwards25519.NewGeneratorPoint())
	return e
}

func (e *Element) Identity() internal.Element {
	e.element.Set(edwards25519.NewIdentityPoint())
	return e
}

// Add returns the sum of the Elements, and does not change the receiver.
func (e *Element) Add(element internal.Element) internal.Element {
	ec := checkElement(element)
	return &Element{edwards25519.NewIdentityPoint().Add(e.element, ec.element)}
}

func (e *Element) Double() internal.Element {
	return e.Add(e)
}

// Subtract returns the difference between the Elements, and does not change the receiver.
func (e *Element) Subtract(element internal.Element) internal.Element {
	ec := checkElement(element)
	return &Element{edwards25519.NewIdentityPoint().Subtract(e.element, ec.element)}
}

func (e *Element) Negate() internal.Element {
	return &Element{edwards25519.NewIdentityPoint().Negate(e.element)}
}

// Multiply returns the scalar multiplication of the receiver element with the given scalar.
func (e *Element) Multiply(scalar internal.Scalar) internal.Element {
	if scalar == nil {
		return &Element{edwards25519.NewIdentityPoint()}
	}

	sc := assert(scalar)

	return &Element{edwards25519.NewIdentityPoint().ScalarMult(sc.scalar, e.element)}
}

func (e *Element) Equal(element internal.Element) int {
	ec := checkElement(element)
	return e.element.Equal(ec.element)
}

// IsIdentity returns whether the element is the Group's identity element.
func (e *Element) IsIdentity() bool {
	id := edwards25519.NewIdentityPoint()
	return e.element.Equal(id) == 1
}

// Copy returns a copy of the element.
func (e *Element) Copy() internal.Element {
	n := edwards25519.NewIdentityPoint()
	if _, err := n.SetBytes(e.element.Bytes()); err != nil {
		panic(err)
	}

	return &Element{element: n}
}

// Decode decodes the input an sets the current element to its value, and returns it.
func (e *Element) Decode(in []byte) (internal.Element, error) {
	if len(in) == 0 {
		return nil, internal.ErrParamNilPoint
	}

	if _, err := e.element.SetBytes(in); err != nil {
		return nil, fmt.Errorf("decoding element : %w", err)
	}

	if e.IsIdentity() {
		return nil, internal.ErrIdentity
	}

	return e, nil
}

// Bytes returns the compressed byte encoding of the element.
func (e *Element) Bytes() []byte {
	return e.element.Bytes()
}
